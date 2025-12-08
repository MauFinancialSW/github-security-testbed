/**
 * JSON API Request Validator
 *
 * Educational demonstration of input validation with intentional vulnerability.
 *
 * VULNERABILITY: No recursion depth limit in JSON parser
 * This allows attackers to send deeply nested JSON objects that cause:
 * 1. Stack overflow (denial of service)
 * 2. Excessive memory consumption
 * 3. Potential remote code execution in some scenarios
 *
 * Fuzzing will discover this vulnerability through systematic exploration
 * of deeply nested JSON structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_KEY_LENGTH 256
#define MAX_VALUE_LENGTH 1024
#define MAX_ARRAY_SIZE 10000

/**
 * JSON token types
 */
typedef enum {
    TOKEN_OBJECT_START,
    TOKEN_OBJECT_END,
    TOKEN_ARRAY_START,
    TOKEN_ARRAY_END,
    TOKEN_STRING,
    TOKEN_NUMBER,
    TOKEN_BOOLEAN,
    TOKEN_NULL,
    TOKEN_COLON,
    TOKEN_COMMA,
    TOKEN_EOF,
    TOKEN_ERROR
} TokenType;

/**
 * JSON token structure
 */
typedef struct {
    TokenType type;
    char value[MAX_VALUE_LENGTH];
    size_t position;
} Token;

/**
 * Parser state
 */
typedef struct {
    const char* input;
    size_t position;
    size_t length;
    int depth;  // Track nesting depth
} ParserState;

/**
 * Initialize parser state
 */
void init_parser(ParserState* state, const char* input) {
    state->input = input;
    state->position = 0;
    state->length = strlen(input);
    state->depth = 0;
}

/**
 * Skip whitespace characters
 */
void skip_whitespace(ParserState* state) {
    while (state->position < state->length &&
           isspace(state->input[state->position])) {
        state->position++;
    }
}

/**
 * Peek at current character without advancing
 */
char peek_char(ParserState* state) {
    if (state->position >= state->length) {
        return '\0';
    }
    return state->input[state->position];
}

/**
 * Consume and return current character
 */
char consume_char(ParserState* state) {
    if (state->position >= state->length) {
        return '\0';
    }
    return state->input[state->position++];
}

/**
 * Parse a JSON string
 */
bool parse_string(ParserState* state, char* output, size_t max_len) {
    skip_whitespace(state);

    if (consume_char(state) != '"') {
        return false;
    }

    size_t i = 0;
    bool escaped = false;

    while (state->position < state->length && i < max_len - 1) {
        char c = consume_char(state);

        if (escaped) {
            // Handle escape sequences
            switch (c) {
                case 'n': output[i++] = '\n'; break;
                case 't': output[i++] = '\t'; break;
                case 'r': output[i++] = '\r'; break;
                case '"': output[i++] = '"'; break;
                case '\\': output[i++] = '\\'; break;
                default: output[i++] = c; break;
            }
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            output[i] = '\0';
            return true;
        } else {
            output[i++] = c;
        }
    }

    return false;
}

/**
 * Parse a JSON number
 */
bool parse_number(ParserState* state, char* output, size_t max_len) {
    skip_whitespace(state);

    size_t i = 0;
    bool has_decimal = false;

    char c = peek_char(state);
    if (c == '-') {
        output[i++] = consume_char(state);
    }

    while (state->position < state->length && i < max_len - 1) {
        c = peek_char(state);

        if (isdigit(c)) {
            output[i++] = consume_char(state);
        } else if (c == '.' && !has_decimal) {
            has_decimal = true;
            output[i++] = consume_char(state);
        } else {
            break;
        }
    }

    output[i] = '\0';
    return i > 0;
}

/**
 * Parse JSON value (recursive)
 *
 * VULNERABILITY: No recursion depth check
 * Deeply nested objects/arrays will overflow the stack
 */
bool parse_value(ParserState* state);

/**
 * Parse JSON object (recursive)
 */
bool parse_object(ParserState* state) {
    skip_whitespace(state);

    if (consume_char(state) != '{') {
        return false;
    }

    // VULNERABILITY: Increment depth but no limit check
    state->depth++;

    skip_whitespace(state);

    // Empty object
    if (peek_char(state) == '}') {
        consume_char(state);
        state->depth--;
        return true;
    }

    // Parse key-value pairs
    while (true) {
        char key[MAX_KEY_LENGTH];

        // Parse key
        if (!parse_string(state, key, MAX_KEY_LENGTH)) {
            return false;
        }

        skip_whitespace(state);

        // Expect colon
        if (consume_char(state) != ':') {
            return false;
        }

        skip_whitespace(state);

        // VULNERABILITY: Recursive call without depth check
        // Deeply nested objects will cause stack overflow
        if (!parse_value(state)) {
            return false;
        }

        skip_whitespace(state);

        char next = peek_char(state);
        if (next == '}') {
            consume_char(state);
            state->depth--;
            return true;
        } else if (next == ',') {
            consume_char(state);
            skip_whitespace(state);
        } else {
            return false;
        }
    }
}

/**
 * Parse JSON array (recursive)
 */
bool parse_array(ParserState* state) {
    skip_whitespace(state);

    if (consume_char(state) != '[') {
        return false;
    }

    // VULNERABILITY: Increment depth but no limit check
    state->depth++;

    skip_whitespace(state);

    // Empty array
    if (peek_char(state) == ']') {
        consume_char(state);
        state->depth--;
        return true;
    }

    // Parse array elements
    size_t element_count = 0;

    while (element_count < MAX_ARRAY_SIZE) {
        // VULNERABILITY: Recursive call without depth check
        if (!parse_value(state)) {
            return false;
        }

        element_count++;
        skip_whitespace(state);

        char next = peek_char(state);
        if (next == ']') {
            consume_char(state);
            state->depth--;
            return true;
        } else if (next == ',') {
            consume_char(state);
            skip_whitespace(state);
        } else {
            return false;
        }
    }

    // Array too large
    return false;
}

/**
 * Parse JSON value (recursive)
 */
bool parse_value(ParserState* state) {
    skip_whitespace(state);

    char c = peek_char(state);

    if (c == '{') {
        // VULNERABILITY: No depth check before recursive call
        return parse_object(state);
    } else if (c == '[') {
        // VULNERABILITY: No depth check before recursive call
        return parse_array(state);
    } else if (c == '"') {
        char str_value[MAX_VALUE_LENGTH];
        return parse_string(state, str_value, MAX_VALUE_LENGTH);
    } else if (c == '-' || isdigit(c)) {
        char num_value[MAX_VALUE_LENGTH];
        return parse_number(state, num_value, MAX_VALUE_LENGTH);
    } else if (strncmp(&state->input[state->position], "true", 4) == 0) {
        state->position += 4;
        return true;
    } else if (strncmp(&state->input[state->position], "false", 5) == 0) {
        state->position += 5;
        return true;
    } else if (strncmp(&state->input[state->position], "null", 4) == 0) {
        state->position += 4;
        return true;
    }

    return false;
}

/**
 * Main JSON request parser
 *
 * This is the entry point that fuzzing will target.
 * The vulnerability will be triggered by deeply nested input.
 */
bool parse_json_request(const char* json_input) {
    if (json_input == NULL || strlen(json_input) == 0) {
        return false;
    }

    ParserState state;
    init_parser(&state, json_input);

    // Parse the root value
    // VULNERABILITY: No maximum depth enforcement
    // Attackers can create JSON like: {a:{b:{c:{d:{e:{...}}}}}}
    // This will recurse until stack overflow
    bool result = parse_value(&state);

    if (!result) {
        return false;
    }

    // Ensure entire input was consumed
    skip_whitespace(&state);
    return state.position >= state.length;
}

/**
 * Validate API request
 *
 * Public API function that validates incoming JSON requests
 */
int validate_api_request(const char* request_body) {
    if (request_body == NULL) {
        fprintf(stderr, "Error: NULL request body\n");
        return -1;
    }

    if (strlen(request_body) == 0) {
        fprintf(stderr, "Error: Empty request body\n");
        return -1;
    }

    // Parse the JSON
    if (!parse_json_request(request_body)) {
        fprintf(stderr, "Error: Invalid JSON\n");
        return -1;
    }

    return 0;  // Success
}

/**
 * Main function for testing
 */
#ifndef FUZZING_BUILD_MODE
int main(int argc, char** argv) {
    // Test cases
    const char* test_cases[] = {
        "{}",
        "{\"key\": \"value\"}",
        "{\"name\": \"John\", \"age\": 30}",
        "[1, 2, 3, 4, 5]",
        "{\"user\": {\"name\": \"Alice\", \"admin\": true}}",
        "{\"items\": [{\"id\": 1}, {\"id\": 2}]}",
        "invalid json",
        NULL
    };

    printf("Testing JSON parser...\n\n");

    for (int i = 0; test_cases[i] != NULL; i++) {
        printf("Test %d: %s\n", i + 1, test_cases[i]);

        int result = validate_api_request(test_cases[i]);

        if (result == 0) {
            printf("  Result: VALID\n");
        } else {
            printf("  Result: INVALID\n");
        }
        printf("\n");
    }

    // Demonstrate vulnerability (will crash with deep nesting)
    printf("Testing with deeply nested object (50 levels)...\n");

    // Build deeply nested JSON
    char deep_json[10000] = "{";
    for (int i = 0; i < 50; i++) {
        strcat(deep_json, "\"a\":{");
    }
    strcat(deep_json, "\"value\":1");
    for (int i = 0; i < 50; i++) {
        strcat(deep_json, "}");
    }
    strcat(deep_json, "}");

    printf("  Input length: %zu bytes\n", strlen(deep_json));
    printf("  Parsing...\n");

    // This will likely crash or hang with very deep nesting
    int result = validate_api_request(deep_json);

    if (result == 0) {
        printf("  Result: VALID (depth: 50)\n");
    } else {
        printf("  Result: INVALID or CRASHED\n");
    }

    return 0;
}
#endif
