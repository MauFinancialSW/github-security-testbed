#!/bin/bash

##############################################################################
# libFuzzer Build Script for JSON Parser
#
# This script compiles the JSON parser with fuzzing instrumentation and
# sanitizers to detect vulnerabilities.
#
# Sanitizers enabled:
# - AddressSanitizer (ASan): Detects memory errors
# - UndefinedBehaviorSanitizer (UBSan): Detects undefined behavior
# - Fuzzer instrumentation: Coverage-guided fuzzing
#
# Usage:
#   chmod +x build_fuzzer.sh
#   ./build_fuzzer.sh
##############################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

echo "================================"
echo "Building libFuzzer harness..."
echo "================================"

# Check if clang is available
if ! command -v clang &> /dev/null; then
    echo "ERROR: clang compiler not found"
    echo "Please install clang (version 6.0 or later)"
    echo ""
    echo "On Ubuntu/Debian:"
    echo "  sudo apt-get install clang"
    echo ""
    echo "On macOS:"
    echo "  brew install llvm"
    echo ""
    exit 1
fi

# Get clang version
CLANG_VERSION=$(clang --version | head -n 1)
echo "Using: $CLANG_VERSION"
echo ""

# Compiler flags
CC="clang"
CFLAGS="-g -O1"

# Sanitizer flags
# - fuzzer: Enable libFuzzer instrumentation
# - address: Enable AddressSanitizer (detects buffer overflows, use-after-free, etc.)
# - undefined: Enable UndefinedBehaviorSanitizer (detects undefined behavior)
SANITIZERS="-fsanitize=fuzzer,address,undefined"

# Additional flags
ADDITIONAL_FLAGS="-DFUZZING_BUILD_MODE -fno-omit-frame-pointer"

# Output binary
OUTPUT="fuzz_json_parser"

# Source files
SOURCES="fuzz_json_parser.c api_validator.c"

echo "Compilation settings:"
echo "  Compiler: $CC"
echo "  Optimization: -O1 (some optimization, preserves debuggability)"
echo "  Sanitizers: fuzzer + AddressSanitizer + UndefinedBehaviorSanitizer"
echo "  Debug info: Enabled (-g)"
echo "  Output: $OUTPUT"
echo ""

# Compile
echo "Compiling..."
$CC $CFLAGS $SANITIZERS $ADDITIONAL_FLAGS $SOURCES -o $OUTPUT

if [ $? -eq 0 ]; then
    echo ""
    echo "================================"
    echo "Build successful!"
    echo "================================"
    echo ""
    echo "Fuzzer binary: ./$OUTPUT"
    echo "File size: $(du -h $OUTPUT | cut -f1)"
    echo ""
    echo "To run the fuzzer:"
    echo "  ./$OUTPUT corpus/"
    echo ""
    echo "Advanced options:"
    echo "  ./$OUTPUT -max_len=10000 -timeout=60 corpus/"
    echo "  ./$OUTPUT -dict=json.dict -jobs=4 corpus/"
    echo "  ./$OUTPUT -help=1  # Show all options"
    echo ""
    echo "Sanitizer options (set via environment):"
    echo "  ASAN_OPTIONS=detect_leaks=1:symbolize=1:abort_on_error=1"
    echo "  UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
    echo ""
else
    echo ""
    echo "================================"
    echo "Build failed!"
    echo "================================"
    exit 1
fi

# Create corpus directory if it doesn't exist
if [ ! -d "corpus" ]; then
    echo "Creating corpus directory..."
    mkdir -p corpus
    echo "Add seed files to corpus/ directory for better fuzzing coverage"
fi

# Check for existing corpus files
CORPUS_COUNT=$(find corpus -type f 2>/dev/null | wc -l)
if [ $CORPUS_COUNT -eq 0 ]; then
    echo ""
    echo "WARNING: No corpus files found in corpus/"
    echo "Add JSON seed files to improve fuzzing effectiveness"
    echo "See corpus/README.txt for examples"
fi

echo ""
echo "Ready to fuzz!"
