# Lagoon - network file systems for AmigaOS 3.x
#
#   make                 native core + tests (gcc, ASan/UBSan): build/host/
#   make test            run the native tests (tests/run_tests.sh)
#   make amiga           vbcc: build/amiga/{lagoon-handler,Lagoon,LagoonPrefs}
#   make package         Installer package build/lagoon-<version>.lha
#
# Core sources are picked up by wildcard: add new .c files to src/core/** and
# they are built for both targets. Tests are tests/t_*.c (one binary each,
# linked with the core and src/host).
VBCC  ?= /opt/amiga/vbcc
NDK   ?= /opt/amiga/ndk/Include_H
NETINC ?= /opt/amiga/ndk/SANA+RoadshowTCP-IP/netinclude
CC    ?= gcc

CORE_SRC  := $(wildcard src/core/*.c src/core/*/*.c)
HOST_SRC  := $(wildcard src/host/*.c)
HDRS      := $(wildcard src/core/*.h src/core/*/*.h src/host/*.h src/amiga/*.h src/amiga/*/*.h)
TESTS     := $(patsubst tests/%.c,build/host/%,$(wildcard tests/t_*.c))

HCFLAGS := -std=c99 -g -O1 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fsanitize=address,undefined \
           -fno-omit-frame-pointer -Isrc/core
HOBJ    := $(patsubst src/%.c,build/host/obj/%.o,$(CORE_SRC) $(HOST_SRC))

all: $(TESTS) build/host/lncli

build/host/obj/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(HCFLAGS) -c -o $@ $<
build/host/liblagoon.a: $(HOBJ)
	ar rcs $@ $^
build/host/t_%: tests/t_%.c tests/testutil.h build/host/liblagoon.a
	$(CC) $(HCFLAGS) -Itests -o $@ $< build/host/liblagoon.a
build/host/lncli: tests/lncli.c build/host/liblagoon.a
	$(CC) $(HCFLAGS) -o $@ $< build/host/liblagoon.a

test: all
	tests/run_tests.sh

# ------------------------------------------------------------- Amiga ----
VC      := PATH=$(VBCC)/bin:$$PATH VBCC=$(VBCC) $(VBCC)/bin/vc +aos68k
ACFLAGS := -c99 -O2 -dontwarn=153 -cpu=68020 -I$(NDK) -I$(NETINC) -Isrc/core -Isrc/amiga -DLN_CRYPTO_ASM
# 68020 assembly for the AES rounds, GHASH and SHA-256 (src/core/crypto/*.s,
# Amiga only; LN_CRYPTO_ASM drops the C versions from aes.c, gcm.c, hash.c)
CORE_ASM := $(wildcard src/core/*/*.s)
AOBJ    := $(patsubst src/%.c,build/amiga/obj/%.o,$(CORE_SRC) src/amiga/sys_amiga.c src/amiga/net_amiga.c src/amiga/mount.c src/amiga/fs_dos.c) \
           $(patsubst src/%.s,build/amiga/obj/%.o,$(CORE_ASM))
HANDLER_SRC := $(wildcard src/amiga/handler/*.c)
CMD_SRC     := $(wildcard src/amiga/cmd/*.c)
PREFS_SRC   := $(wildcard src/amiga/prefs/*.c)

build/amiga/obj/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(VC) $(ACFLAGS) -c -o $@ $<
build/amiga/obj/%.o: src/%.s
	@mkdir -p $(dir $@)
	$(VBCC)/bin/vasmm68k_mot -quiet -Fhunk -m68020 -nowarn=62 -o $@ $<
build/amiga/liblagoon.lib: $(AOBJ)
	@mkdir -p $(dir $@)
	cat $^ > $@

amiga: build/amiga/liblagoon.lib
	@if [ -n "$(HANDLER_SRC)" ]; then $(MAKE) build/amiga/lagoon-handler; fi
	@if [ -n "$(CMD_SRC)" ]; then $(MAKE) build/amiga/Lagoon; fi
	@if [ -n "$(PREFS_SRC)" ]; then $(MAKE) build/amiga/LagoonPrefs; fi

# the handler has its own entry point (no C start-up code): see src/amiga/handler
build/amiga/lagoon-handler: $(patsubst src/%.c,build/amiga/obj/%.o,$(HANDLER_SRC)) build/amiga/liblagoon.lib
	$(VC) -nostdlib -s -o $@ $(patsubst src/%.c,build/amiga/obj/%.o,$(HANDLER_SRC)) build/amiga/liblagoon.lib -lvc -lamiga
build/amiga/Lagoon: $(patsubst src/%.c,build/amiga/obj/%.o,$(CMD_SRC)) build/amiga/liblagoon.lib
	$(VC) -s -o $@ $(patsubst src/%.c,build/amiga/obj/%.o,$(CMD_SRC)) build/amiga/liblagoon.lib -lamiga
build/amiga/LagoonPrefs: $(patsubst src/%.c,build/amiga/obj/%.o,$(PREFS_SRC)) build/amiga/liblagoon.lib
	$(VC) -s -o $@ $(patsubst src/%.c,build/amiga/obj/%.o,$(PREFS_SRC)) build/amiga/liblagoon.lib -lamiga

package: all amiga
	tools/mkpackage.sh

.PHONY: all test amiga package
.SECONDARY:

# lncli for the Amiga (tests/lncli.c with the C library start-up): exercises
# the backends on a real 68k + bsdsocket.library (tests/amiga/run_emu.sh)
build/amiga/lncli: tests/lncli.c build/amiga/liblagoon.lib
	$(VC) $(ACFLAGS) -o $@ tests/lncli.c build/amiga/liblagoon.lib -lamiga
amiga: build/amiga/lncli

# crypto throughput benchmark (tests/amiga/cryptobench.c): run it under
# vamos -C 68020 or in the emulator; the host build is for comparing digests
build/amiga/cryptobench: tests/amiga/cryptobench.c build/amiga/liblagoon.lib
	$(VC) $(ACFLAGS) -o $@ tests/amiga/cryptobench.c build/amiga/liblagoon.lib -lamiga
build/host/cryptobench: tests/amiga/cryptobench.c build/host/liblagoon.a
	$(CC) $(HCFLAGS) -o $@ $< build/host/liblagoon.a

# lnsrv: the SMB server core sharing host directories (tests/servers/lagoon)
build/host/lnsrv: tests/lnsrv.c build/host/liblagoon.a
	$(CC) $(HCFLAGS) -o $@ $< build/host/liblagoon.a
all: build/host/lnsrv
