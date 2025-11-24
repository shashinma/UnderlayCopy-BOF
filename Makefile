all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -masm=intel -c UnderlayCopyBOF/entry.c -o _bin/underlaycopy.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/underlaycopy.x64.o) && echo '[+] underlaycopy x64' || echo '[!] underlaycopy x64'
	@(i686-w64-mingw32-gcc -I _include -Os -masm=intel -c UnderlayCopyBOF/entry.c -o _bin/underlaycopy.x86.o -DBOF && i686-w64-mingw32-strip --strip-unneeded _bin/underlaycopy.x86.o) && echo '[+] underlaycopy x86' || echo '[!] underlaycopy x86'

clean:
	@(rm -rf _bin)

