# Makefile for Test Malware Simulator
# Compiles the test program for malware analysis testing

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = test_malware_simulator
SOURCE = test_malware_simulator.c

.PHONY: all clean test help

all: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "Compiling $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)
	@echo "Build complete: $(TARGET)"
	@echo ""
	@echo "To run analysis:"
	@echo "  ltrace-full ./$(TARGET)"
	@echo "  trace-malware ./$(TARGET)"

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)
	rm -f /tmp/test_*.txt /tmp/test_*.sh /tmp/.bashrc_test
	rm -f /tmp/*.service /tmp/crontab_test
	rm -rf /tmp/test_dir
	@echo "Clean complete"

test: $(TARGET)
	@echo "Running test program..."
	./$(TARGET)

help:
	@echo "Test Malware Simulator - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile the test program (default)"
	@echo "  clean   - Remove compiled binary and test files"
	@echo "  test    - Compile and run the test program"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Analysis commands:"
	@echo "  ltrace-full ./$(TARGET)           - Full ltrace analysis"
	@echo "  trace-malware ./$(TARGET)         - Combined strace/ltrace"
	@echo "  strace -f ./$(TARGET)             - System call trace"
	@echo "  ltrace -f ./$(TARGET)             - Library call trace"
