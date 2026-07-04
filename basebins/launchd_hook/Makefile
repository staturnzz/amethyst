CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID = $(shell which ldid)

CFLAGS := -DLAUNCHD_HOOK=1 -I./include -I../common/include -isysroot $(SDK) -mios-version-min=12.0 -fno-objc-arc \
	-arch arm64 -arch arm64e -Werror -Wall -Wno-unused-variable -Wno-unused-function -fvisibility=hidden -fvisibility-inlines-hidden

LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem -dynamiclib -framework CoreFoundation -framework ImageIO \
	-framework CoreGraphics -framework IOSurface -framework IOKit ../resources/IOMobileFramebuffer.tbd \
	-Wl,-sectcreate,__DATA,__splashscreen,../resources/splashscreen.jp2

SRC = $(wildcard src/*.c) $(wildcard src/*.m) ../common/src/basebin_hook.c ../common/src/basebin_instructions.c \
	../common/src/basebin_macho.c ../common/src/basebin_memory.c ../common/src/basebin_memory.s \
	../common/src/basebin_ptrauth.s ../common/src/basebin_util.c

all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o launchd_hook.dylib $^
	$(STRIP) -x launchd_hook.dylib
	$(LDID) -S launchd_hook.dylib

clean:
	@rm -rf launchd_hook.dylib
	@rm -rf launchd_hook.dylib.dSYM
	@rm -rf *.o
