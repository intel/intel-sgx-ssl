# Compiler and linker
CC := afl-clang-fast
CXX := afl-clang-fast++
LD := afl-clang-fast++

BIN := $(FUZZER)

# Compiler and linker flags
CFLAGS := -I../Linux/package/include -Iinclude -pthread -m64 -fno-omit-frame-pointer -g -Wa,--noexecstack -Qunused-arguments -Wall -O0 -g -fno-sanitize=alignment -DOPENSSL_BUILDING_OPENSSL -DPEDANTIC
CPPFLAGS := $(CFLAGS) -std=c++11
CFLAGS := $(CFLAGS) -std=c11
LDFLAGS := -pthread -m64 -fno-omit-frame-pointer -g -Wa,--noexecstack -Qunused-arguments -Wall -O0 -g -fno-sanitize=alignment

# Source files
SOURCES := driver.c $(BIN).c

# Object files
OBJECTS := $(SOURCES:.c=.o)

# Executable name
EXECUTABLE := $(BIN)

# Default target
all: $(EXECUTABLE)

# Link the executable
$(EXECUTABLE): $(OBJECTS) sgxssl_fuzz_common.o
	$(LD) $(LDFLAGS) -o $@ $^ -L../Linux/package/lib64/ -Wl,--no-whole-archive -Wl,--start-group  -lsgx_tsgxssl_crypto -lsgx_tsgxssl -Wl,--end-group  -ldl -pthread -L/usr/lib/gcc/x86_64-linux-gnu/11/ -lstdc++ -Wl,--defsym,__errno=0

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MF $*.d.tmp -MT $@ -c -o $@ $<

sgxssl_fuzz_common.o: sgxssl_fuzz_common.cpp
	$(CXX) $(CPPFLAGS) -MMD -MF $*.d.tmp -MT $@ -c -o $@ $<

# Include dependency files
-include $(SOURCES:.c=.d)

# Clean target
clean:
	 rm -f *.o *.d *.tmp $(EXECUTABLE) *_fuzz

#run: all
#	afl-fuzz -i fuzz/corpora/$(BIN) -o fuzz/corpora/$(BIN)/out fuzz/$(BIN)

.PHONY: all clean #run
