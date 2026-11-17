# AdaptixBOFKit build
#
# Builds every src/*.c into a position-independent x64 COFF object that the
# Adaptix Beacon agent can execute with `execute bof`.
#
# Requirements:
#   apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 make

CC      := x86_64-w64-mingw32-gcc
STRIP   := x86_64-w64-mingw32-strip
CFLAGS  ?= -Iinclude -Os -w -DBOF -D_WIN32_WINNT=0x0601 \
           -fno-jump-tables -fno-asynchronous-unwind-tables \
           -fno-stack-protector -mno-stack-arg-probe -fno-builtin \
           -fno-tree-loop-distribute-patterns

SRC     := $(wildcard src/*.c)
OBJ     := $(patsubst src/%.c,_bin/%.x64.o,$(SRC))

.PHONY: all clean list

all: $(OBJ)

_bin:
	@mkdir -p _bin

_bin/%.x64.o: src/%.c include/beacon.h include/bofdefs.h include/helpers.h include/ldaphelpers.h | _bin
	@printf '  [cc] %-28s\n' '$*.c'
	@$(CC) $(CFLAGS) -c $< -o $@
	@$(STRIP) --strip-unneeded $@ 2>/dev/null || true

list:
	@printf '%s\n' $(notdir $(basename $(SRC)))

clean:
	@rm -rf _bin
