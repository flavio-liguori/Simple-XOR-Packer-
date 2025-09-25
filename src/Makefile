# XOR Packer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
TARGET = stub_generate
SOURCE = stub_generate.c
SHELL_SCRIPT = packer.sh

.PHONY: all build clean install test help


all: build

build: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "Compiling XOR Packer..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)
	@echo "Build completed: $(TARGET)"

install: build
	@echo "Installing XOR Packer..."
	chmod +x $(SHELL_SCRIPT)
	@echo "Installation completed"
	@echo "Usage: ./$(SHELL_SCRIPT) help"

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)
	rm -f *.c.out
	rm -f packed_*
	rm -f test_*
	rm -rf *.dSYM
	@echo "Cleanup completed"

test: build
	@echo "Running quick test..."
	@echo '#include <stdio.h>' > test_simple.c
	@echo 'int main(){printf("Test OK\\n");return 0;}' >> test_simple.c
	$(CC) -o test_simple test_simple.c
	./$(SHELL_SCRIPT) test ./test_simple
	rm -f test_simple test_simple.c packed_test_simple*
	@echo "Test completed successfully"

test-system: build
	@echo "Testing with system binary..."
	./$(SHELL_SCRIPT) pack /bin/echo test_echo
	@echo "Testing packed executable:"
	./test_echo "Hello from packed echo!"
	rm -f test_echo test_echo.c
	@echo "System test completed"

help:
	@echo "XOR Packer Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make build        - Compile the stub generator"
	@echo "  make install      - Build and setup permissions"
	@echo "  make clean        - Remove generated files"
	@echo "  make test         - Run quick test"
	@echo "  make test-system  - Test with system binary"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "After installation, use:"
	@echo "  ./packer.sh help  - Show packer usage"

info:
	@echo "XOR Packer Project Info"
	@echo "=========================="
	@echo "Source file:    $(SOURCE)"
	@echo "Target binary:  $(TARGET)"
	@echo "Shell script:   $(SHELL_SCRIPT)"
	@echo "Compiler:       $(CC)"
	@echo "Flags:          $(CFLAGS)"
	@echo ""
	@ls -la $(SOURCE) $(SHELL_SCRIPT) 2>/dev/null || echo "Files not found"
	@if [ -f $(TARGET) ]; then echo "Built: $(TARGET)"; else echo "Not built: $(TARGET)"; fi