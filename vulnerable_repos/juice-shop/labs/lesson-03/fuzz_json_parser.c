/**
 * libFuzzer Harness for JSON Parser
 *
 * This fuzzing harness targets the parse_json_request() function in api_validator.c
 * to discover vulnerabilities through automated input exploration.
 *
 * The fuzzer will:
 * 1. Generate diverse JSON inputs (guided by coverage feedback)
 * 2. Feed them to the parser
 * 3. Detect crashes, hangs, and memory corruption
 * 4. Save crash-inducing inputs for analysis
 *
 * Expected to discover:
 * - Stack overflow from deep nesting
 * - Memory corruption from malformed input
 * - Assertion failures
 * - Undefined behavior
 *
 * Compilation:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -DFUZZING_BUILD_MODE \
 *         fuzz_json_parser.c api_validator.c \
 *         -o fuzz_json_parser
 *
 * Execution:
 *   ./fuzz_json_parser -max_len=10000 -timeout=60 corpus/
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Define before including api_validator.c
#define FUZZING_BUILD_MODE

// Declare the function we're fuzzing
extern bool parse_json_request(const char* json_input);
extern int validate_api_request(const char* request_body);

/**
 * libFuzzer entry point
 *
 * This function is called by libFuzzer for each generated input.
 *
 * @param Data Pointer to fuzzer-generated input data
 * @param Size Length of input data in bytes
 * @return 0 (return value is ignored by libFuzzer)
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ignore empty inputs
    if (Size == 0) {
        return 0;
    }

    // Ignore inputs that are too large (prevent excessive memory usage)
    if (Size > 100000) {
        return 0;
    }

    // Create null-terminated string from fuzzer input
    // We need to copy because fuzzer data is not null-terminated
    char *json_input = (char *)malloc(Size + 1);
    if (json_input == NULL) {
        return 0;  // Out of memory, skip this input
    }

    memcpy(json_input, Data, Size);
    json_input[Size] = '\0';

    // Fuzz the main parsing function
    // The fuzzer will detect crashes, hangs, and sanitizer violations
    parse_json_request(json_input);

    // Also fuzz the validation wrapper
    validate_api_request(json_input);

    // Clean up
    free(json_input);

    return 0;  // Non-zero return values are reserved for future use
}

/**
 * Custom initialization (optional)
 *
 * Called once before fuzzing starts. Can be used to:
 * - Initialize global state
 * - Load dictionaries
 * - Set up signal handlers
 */
__attribute__((constructor))
void init_fuzzer() {
    // Suppress stderr output for cleaner fuzzer output
    // Comment this out if you need to see parser errors
    // freopen("/dev/null", "w", stderr);
}

/**
 * Custom mutator (optional, advanced)
 *
 * This can be implemented to guide fuzzing with JSON-specific mutations:
 * - Add/remove nesting levels
 * - Insert special characters
 * - Generate valid JSON structures
 *
 * For now, we rely on libFuzzer's default mutation strategies.
 */

// Uncomment to implement custom mutator:
/*
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    // Example: Increase nesting depth
    // Implementation left as exercise
    return Size;
}
*/

/**
 * Custom cross-over (optional, advanced)
 *
 * Combines two inputs to create new test case.
 * Useful for JSON where combining valid fragments can find bugs.
 */

// Uncomment to implement custom crossover:
/*
size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                  const uint8_t *Data2, size_t Size2,
                                  uint8_t *Out, size_t MaxOutSize,
                                  unsigned int Seed) {
    // Example: Combine JSON objects
    // Implementation left as exercise
    return 0;
}
*/
