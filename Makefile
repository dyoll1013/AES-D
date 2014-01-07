DFLAGS += -m64 -Isource
NASMFLAGS += 
VPATH = source:build

NAME = $(shell uname)
ifeq ($(NAME), Linux)
	NASMFLAGS += -f elf64
endif
ifeq ($(NAME), Darwin)
	NASMFLAGS += -f macho64
endif

aestool: DFLAGS += -release -O -inline
aestool: aes.o aes_asm.o aestool.d
	dmd $(DFLAGS) build/aes.o build/aes_asm.o source/aestool.d -ofbuild/aestool

speedtest: DFLAGS += -release -O -inline
speedtest: aes.o speedtest.d aes_asm.o
	dmd $(DFLAGS) build/aes.o build/aes_asm.o source/speedtest.d -ofbuild/speedtest

test: source/aes/*.d aes_asm.o
	dmd $(DFLAGS) -main -unittest source/aes/*.d build/aes_asm.o -ofbuild/test
	build/test

aes_asm.o: aes/aesni.asm
	# nasm won't create the directory automatically
	test -d build || mkdir build
	nasm $(NASMFLAGS) -o build/aes_asm.o source/aes/aesni.asm

aes.o: source/aes/*.d
	dmd $(DFLAGS) -c source/aes/*.d -ofbuild/aes.o

.PHONY: clean
clean:
	rm build/*