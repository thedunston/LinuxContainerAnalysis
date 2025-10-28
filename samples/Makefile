# Makefile for Test Malware Simulator.
# Compiles the test program for malware analysis testing.

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = test_malware_simulator
SOURCE = test_malware_simulator.c

.PHONY: all test help

all: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "Compiling $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)
	@echo "Build complete: $(TARGET)"
	@echo "Load the file into the container::"
	@echo "  ./linux_malware_analysis_container.sh samples/test_malware_simulator"
	@echo "    When the container starts, run: ltrace-full samples/test_malware_simulator"

help:
	@echo "Test Malware Simulator - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Compile the test program
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Analysis commands:"
	@echo "  ./linux_malware_analysis_container.sh samples/test_malware_simulator"
	@echo "    When the container starts, run: ltrace-full samples/test_malware_simulator"
	@echo "Other Commands:"
	@echo "  ltrace-full ./$(TARGET)           - Full ltrace analysis"
	@echo "  trace-malware ./$(TARGET)         - Combined strace/ltrace"
	@echo "  strace -f ./$(TARGET)             - System call trace"
	@echo "  ltrace -f ./$(TARGET)             - Library call trace"
