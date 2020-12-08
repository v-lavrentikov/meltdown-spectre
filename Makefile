CC=gcc
MSC=x86_64-w64-mingw32-gcc

all: meltdown spectre_v1 spectre_v4

meltdown:
	$(CC) $@.c -o $@ tools.c -m64 -DMELTDOWN=meltdown
	$(CC) $@.c -o $@_nonull tools.c -m64 -DMELTDOWN=meltdown_nonull
	$(CC) $@.c -o $@_fast tools.c -m64 -DMELTDOWN=meltdown_fast

spectre_v1:
	$(CC) $@.c -o $@ tools.c -m64

spectre_v4:
	$(CC) $@.c -o $@ tools.c -m64
	$(CC) $@.c -o $@_asm tools.c -m64 -DASM

win:
	$(MSC) spectre_v1.c tools.c -o spectre_v1.exe -mconsole -m64
	$(MSC) spectre_v4.c tools.c -o spectre_v4.exe -mconsole -m64
	$(MSC) spectre_v4.c tools.c -o spectre_v4_asm.exe -mconsole -m64 -DASM

clean:
	rm -f *.exe meltdown meltdown_nonull meltdown_fast spectre_v1 spectre_v4 spectre_v4_asm
