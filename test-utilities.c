// Application to test unpack utilities
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


int test_lfsr_step(void) {
  // A properly created LFSR should do two things
  //  1. It should generate specific new state based on a known initial state
  //  2. It should iterate through all 2^16 integers, once each (except 0)

  // Create an array to track if the LFSR hit each integer (except 0)
  // 2^16 (65536) possibilities
  bool* lfsr_states = malloc_and_check(65536);
  memset(lfsr_states, 0, 65536);

  // Initial 16 LFSR states
  uint16_t correct_lfsr_states[16] = {
    0x1337, 0x099B, 0x84CD, 0x4266,
    0x2133, 0x1099, 0x884C, 0xC426,
    0x6213, 0xB109, 0x5884, 0x2C42,
    0x1621, 0x0B10, 0x8588, 0x42C4
  };

  // Step the LFSR until a state repeats
  bool repeat        = false;
  size_t steps       = 0;
  uint16_t new_state = 0x1337; // known initial state
  while (!repeat) {

    // Iterate LFSR
    steps++;
    new_state = lfsr_step(new_state); //so as not to save any state internally

    // Check if this state has already been reached
    repeat = lfsr_states[new_state];
    lfsr_states[new_state] = true;

    // Check first 16 LFSR steps
    if (steps < 16) {
      if (new_state != correct_lfsr_states[steps]) {
        printf("ERROR: at step %lu, expected state 0x%04X but received state 0x%04X\n",
            steps, correct_lfsr_states[steps], new_state);
        free(lfsr_states);
        return 1;
      }
    }
  }

  // Check that all integers were hit. Should take 2^16 (65536) steps (2^16-1 integers, plus a repeat)
  if (steps != 65536) {
    printf("ERROR: expected %d iterations before a repeat, but ended after %lu steps\n", 65536, steps);
    free(lfsr_states);
    return 1;
  }

  // Cleanup
  free(lfsr_states);
  return 0;
}

//------------------------------------------
//          CHECKSUMMING TESTS:
//-------------------------------------------

// Here's an example testcase
// It's written for the `calculate_checksum()` function, but the same ideas
//  would work for any function you want to test
// Feel free to copy it and adapt it to create your own tests
int example_test(void) {
  // Create input data to test with
  // If you wanted to test a header, these would be bytes of the header with
  //    meaningful bytes in appropriate places
  // If you want to test one of the other functions, they can be any bytes
  uint8_t input_data[] = {0x01, 0x03, 0x04, };

  // Create an "expected" result to compare against
  // If you're testing header parsing, you will likely need one of these for
  //    each config field. If you're testing decryption or decompression, this
  //    should be an array of expected output_data bytes
  uint16_t expected_checksum_value = 0x0008;

  // Actually run your code
  // Note that `sizeof(input_data)` actually returns the number of bytes for the
  //    array because it's a local variable (`sizeof()` generally doesn't return
  //    buffer lengths in C for arrays that are passed in as arguments)
  uint16_t calculated_checksum_value = calculate_checksum(input_data, sizeof(input_data));

  // Compare the results
  // This might need to be multiple comparisons or even a loop that compares many bytes
  // `memcmp()` in the C standard libary might be a useful function here!
  // Note, you don't _need_ the CHECK() functions like we used in CS211, you
  //    can just return 1 then print that there was an error
  if (calculated_checksum_value != expected_checksum_value) {
    // Test failed! Return 1 to signify failure
    return 1;
  }

  // Test succeeded! Return 0 to signify success
  return 0;
}

// empty imput:
int test_checksum_empty(void) {
  uint16_t got = calculate_checksum(NULL, 0);
  if (got != 0) {
    printf("FAIL test_checksum_empty: got 0x%04X expected 0x0000\n", got);
    return 1;
  }
  return 0;
}

// single byte:
int test_checksum_single_byte(void) {
  uint8_t data[] = { 0xAB };  // decimal 171
  uint16_t got = calculate_checksum(data, sizeof(data));
  if (got != 0x00AB) {
    printf("FAIL test_checksum_single_byte: got 0x%04X expected 0x00AB\n", got);
    return 1;
  }
  return 0;
}
// // overflow-----------------------------------
// int test_checksum_overflow_wrap(void) {
//   // 0xFFFF + 0x0002 = 0x10001 -> wraps to 0x0001 in uint16_t
//   uint8_t data[] = { 0xFF, 0xFF, 0x02 }; // 255 + 255 + 2 = 512 = 0x0200 (not overflow)
//   // The above does NOT overflow 16-bit, so we need a larger sum.

//   // Better: use many 0xFF bytes. 257 bytes of 0xFF = 257*255 = 655...?
//   // 255*257 = 255*(256+1) = 65280 + 255 = 65535 = 0xFFFF
//   // Then add 0x02 -> 0x0001 after wrap.
//   uint8_t big[258];
//   for (int i = 0; i < 257; i++) {
//     big[i] = 0xFF;
//   }
//   big[257] = 0x02;

//   uint16_t got = calculate_checksum(big, sizeof(big));
//   if (got != 0x0001) {
//     printf("FAIL test_checksum_overflow_wrap: got 0x%04X expected 0x0001\n", got);
//     return 1;
//   }
//   return 0;
// }


//--------------------------------------
//          PARSE_HEADER TESTS:
//--------------------------------------
int test_parse_header(void) {
  // input data
  // This array is exactly the first 38 bytes of the file header
  // 02 13 = magic (big-endian)
  // 03    = version
  // E0    = flags (compressed+encrypted+checksummed)
  // next 8 bytes  = orig_data_size (little-endian)
  // next 8 bytes  = data_size (little-endian)
  // next 16 bytes = dictionary (because compressed)
  // last 2 bytes  = checksum (because checksummed, big-endian)
  uint8_t hdr[] = {0x02, 0x13, 0x03, 0xE0,
    0x07, 0x35, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xA9, 0x59, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x80, 0x01, 0x02, 0x40, 0x04, 0xC0, 0x08,
    0x03, 0x10, 0x20, 0x06, 0xA0, 0x60, 0x81, 0x30,
    0x77, 0xB4};

  packlab_config_t cfg;

  // fill cfg with a pattern so we know parse_header actually parses what is should
  memset(&cfg, 0xAB, sizeof(cfg));

  // call the function
  parse_header(hdr, sizeof(hdr), &cfg);

  // is_valid should be true for a correct header
  if (!cfg.is_valid) {
    printf("FAIL test_parse_header: is valid was false\n");
    return 1;
  }

  // header len = 38 => dict + checksum included
  if(cfg.header_len != 38){
    printf("FAIL test_parse_header: header len got %lu expected 38\n", (unsigned long)cfg.header_len);
    return 1;
  }

  //flags are: compressed/encryption/checksummed
  if(!cfg.is_compressed){
    printf("FAIL test_parse_header: is iscompressed expected true\n");
    return 1;
  }
  if(!cfg.is_encrypted){
    printf("FAIL test_parse_header: is is_encrypted expected true\n");
    return 1;
  }
  if(!cfg.is_checksummed){
    printf("FAIL test_parse_header: is is_checksummed expected true\n");
    return 1;
  }
  
  // no continuation
  if(cfg.should_continue){
    printf("FAIL test_parse_header: is should_continue expected false\n");
    return 1;
  }
  if(cfg.should_float){
    printf("FAIL test_parse_header: is should_float expected false\n");
    return 1;
  }
  if(cfg.should_float3){
    printf("FAIL test_parse_header: is should_float3 expected false\n");
    return 1;
  }

  // original data size: 0x193507 in LE = 1,651,975
  if (cfg.orig_data_size != 1651975ULL){
    printf("FAIL test_parse_header: orig_data_size got %lu expected %lu\n", (unsigned long)cfg.orig_data_size, (unsigned long) 1651975ULL);
    return 1;
  }

  // packed data size: 0x1959A9 = 1661353
  if (cfg.data_size != 1661353ULL){
    printf("FAIL test_parse_header: data_size data got %lu expected %lu\n", (unsigned long)cfg.data_size, (unsigned long) 1661353ULL);
    return 1;
  }

  // dictionary bytes we expect: 16bytes
  uint8_t expected_dict[DICTIONARY_LENGTH] = {
    0x00, 0x80, 0x01, 0x02, 0x40, 0x04, 0xC0, 0x08,
    0x03, 0x10, 0x20, 0x06, 0xA0, 0x60, 0x81, 0x30
  };

  // memcmp returns 0 when arrays match exactly
  if (memcmp(cfg.dictionary_data, expected_dict, DICTIONARY_LENGTH) != 0) {
    printf("FAIL test_parse_header: dictionary bytes mismatch\n");
    return 1;
  }
  // checksum: 0x77B4 BE
    if(cfg.checksum_value != 0x77B4){
      printf("FAIL test_parse_header: checksum_value got 0x%04X expected 0x77B4\n", cfg.checksum_value);
      return 1;
    }
  // all test passed?
  return 0;

}
// Minimal valid header (20 bytes) with all flags off
  // 20-byte header:
  // magic 02 13, version 03, flags 00
  // orig_data_size = 16 (little-endian uint64)
  // data_size      = 16 (little-endian uint64)
  int test_parse_header_minimal_20(void) {
    uint8_t hdr[20] = {
      0x02, 0x13, 0x03, 0x00,
      0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    packlab_config_t cfg;
    memset(&cfg, 0xCD, sizeof(cfg));
    parse_header(hdr, sizeof(hdr), &cfg);

    if (!cfg.is_valid) {
      printf("FAIL test_parse_header_minimal_20: is_valid was false\n");
      return 1;
    }
  
  // With no options enabled, header_len should be 20
    if (cfg.header_len != 20) {
    printf("FAIL test_parse_header_minimal_20: header_len got %lu expected 20\n",
           (unsigned long)cfg.header_len);
    return 1;
  }

  // All flags should be false
    if (cfg.is_compressed || cfg.is_encrypted || cfg.is_checksummed ||
      cfg.should_continue || cfg.should_float || cfg.should_float3) {
    printf("FAIL test_parse_header_minimal_20: expected all flags false\n");
    return 1;
  }

  // Sizes should match what we encoded
    if (cfg.orig_data_size != 16ULL || cfg.data_size != 16ULL) {
    printf("FAIL test_parse_header_minimal_20: size fields mismatch\n");
    return 1;
  }

  return 0;
}

// Valid header with checksum only (22 bytes)
int test_parse_header_checksum_only_22(void) {

  // flags = 0x20 means bit5 (Checksummed?) is set
  // checksum stored at the end (2 bytes, big-endian)
  uint8_t hdr[22] = {
    0x02, 0x13, 0x03, 0x20,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // orig=1
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data=2
    0xBE, 0xEF // checksum = 0xBEEF (big-endian)
  };

  packlab_config_t cfg;
  memset(&cfg, 0xEF, sizeof(cfg));
  parse_header(hdr, sizeof(hdr), &cfg);

  if (!cfg.is_valid) {
    printf("FAIL test_parse_header_checksum_only_22: is_valid was false\n");
    return 1;
  }

  // 20 base bytes + 2 checksum bytes = 22
  if (cfg.header_len != 22) {
    printf("FAIL test_parse_header_checksum_only_22: header_len got %lu expected 22\n",
           (unsigned long)cfg.header_len);
    return 1;
  }

  // Checksummed should be true; compressed should be false here.
  if (!cfg.is_checksummed || cfg.is_compressed) {
    printf("FAIL test_parse_header_checksum_only_22: flags mismatch\n");
    return 1;
  }

  if (cfg.checksum_value != 0xBEEF) {
    printf("FAIL test_parse_header_checksum_only_22: checksum_value got 0x%04X expected 0xBEEF\n",
           cfg.checksum_value);
    return 1;
  }

  return 0;
}

// Valid header with compression only (36 bytes)
int test_parse_header_compression_only_36(void) {

  // flags = 0x80 means bit7 (Compressed?) is set
  // dictionary appears (16 bytes) immediately after base 20 bytes
  uint8_t hdr[36] = {
    0x02, 0x13, 0x03, 0x80,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // orig=3
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data=4
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // dict[0..7]
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F  // dict[8..15]
  };

  packlab_config_t cfg;
  memset(&cfg, 0x11, sizeof(cfg));

  parse_header(hdr, sizeof(hdr), &cfg);

  if (!cfg.is_valid) {
    printf("FAIL test_parse_header_compression_only_36: is_valid was false\n");
    return 1;
  }

  // 20 base bytes + 16 dictionary bytes = 36
  if (cfg.header_len != 36) {
    printf("FAIL test_parse_header_compression_only_36: header_len got %lu expected 36\n",
           (unsigned long)cfg.header_len);
    return 1;
  }

  if (!cfg.is_compressed || cfg.is_checksummed) {
    printf("FAIL test_parse_header_compression_only_36: flags mismatch\n");
    return 1;
  }

  // Verify dictionary bytes copied correctly
  uint8_t expected_dict[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
  };

  if (memcmp(cfg.dictionary_data, expected_dict, 16) != 0) {
    printf("FAIL test_parse_header_compression_only_36: dictionary mismatch\n");
    return 1;
  }

  return 0;
}

// INVALID CASES:
// too short
int test_parse_header_too_short(void){
  uint8_t hdr[10] = {0};
  packlab_config_t cfg;
  memset(&cfg, 0x22, sizeof(cfg)); // fill with junk first

  parse_header(hdr, sizeof(hdr), &cfg);

  // parse_header should mark invalid
  if (cfg.is_valid) {
    printf("FAIL test_parse_header_too_short: expected invalid but got valid\n");
    return 1;
  }
  return 0;
}

//invalid magic:
int test_parse_header_wrong_magic(void) {
  uint8_t hdr[20] = {
    0xDE, 0xAD, 0x03, 0x00,
    0x10, 0,0,0,0,0,0,0,
    0x10, 0,0,0,0,0,0,0
  };

  packlab_config_t cfg;
  memset(&cfg, 0x33, sizeof(cfg));

  parse_header(hdr, sizeof(hdr), &cfg);

  if (cfg.is_valid) {
    printf("FAIL test_parse_header_wrong_magic: expected invalid but got valid\n");
    return 1;
  }
  return 0;
}
// wrong version
int test_parse_header_wrong_version(void) {
  uint8_t hdr[20] = {
    0x02, 0x13, 0x99, 0x00,    // wrong version byte
    0x10, 0,0,0,0,0,0,0,
    0x10, 0,0,0,0,0,0,0
  };

  packlab_config_t cfg;
  memset(&cfg, 0x44, sizeof(cfg));
  parse_header(hdr, sizeof(hdr), &cfg);

  if (cfg.is_valid) {
    printf("FAIL test_parse_header_wrong_version: expected invalid but got valid\n");
    return 1;
  }
  return 0;
}
// compressed flag set but header is only 20 bytes (missing dictionary)
int test_parse_header_compressed_but_short(void) {
  uint8_t hdr[20] = {
    0x02, 0x13, 0x03, 0x80,    // compressed bit set
    0x01, 0,0,0,0,0,0,0,
    0x01, 0,0,0,0,0,0,0
  };

  packlab_config_t cfg;
  memset(&cfg, 0x55, sizeof(cfg));
  parse_header(hdr, sizeof(hdr), &cfg);

  if (cfg.is_valid) {
    printf("FAIL test_parse_header_compressed_but_short: expected invalid but got valid\n");
    return 1;
  }
  return 0;
}

// checksummed flag set but header is only 20 bytes (missing checksum)
int test_parse_header_checksummed_but_short(void) {
  uint8_t hdr[20] = {
    0x02, 0x13, 0x03, 0x20,    // checksummed bit set
    0x01, 0,0,0,0,0,0,0,
    0x01, 0,0,0,0,0,0,0
  };

  packlab_config_t cfg;
  memset(&cfg, 0x66, sizeof(cfg));

  parse_header(hdr, sizeof(hdr), &cfg);

  if (cfg.is_valid) {
    printf("FAIL test_parse_header_checksummed_but_short: expected invalid but got valid\n");
    return 1;
  }
  return 0;
}

//-------------------------------------
//        DECRYPTION TESTS
//---------------------------------------
int test_decrypt_4byte_example_in_handout(void) {
  // input data = [0x60, 0x5A, 0xFF, 0xB7]
  // encryption_key = initial LFSR state = 0x1337
  // LFSR outputs: 0x099B, 0X84CD
  // XOR output_data: [0xFB, 0x53, 0x32, 0x33]

  uint8_t input_data[] = {0x60, 0x5A, 0xFF, 0xB7}; // encrypted bytes
  uint8_t output_data[sizeof(input_data)]; // weher decrypted bytes will go
  uint8_t expected[] = {0xFB, 0x53, 0x32, 0x33}; // expected decrypted bytes

  // decrypt function
  decrypt_data(input_data, sizeof(input_data), output_data, sizeof(output_data), 0x1337);

  // comparison
  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decrypt_4byte_example_in_handout: output mismatch\n ");
    return 1;
  }
  return 0;
}
// odd number of bytes
int test_decrypt_1byte_example_in_handout(void) {
  // input_data  = [0x21]
  // encryption_key = 0x1337
  // first LFSR output = 0x099B => LSB = 0x9B
  // 0x21 ^ 0x9B = 0xBA
  // output_data = [0xBA]

  uint8_t input_data[] = {0x21};
  uint8_t output_data[sizeof(input_data)];

  uint8_t expected[] = {0xBA};

  decrypt_data(input_data, sizeof(input_data), output_data, sizeof(output_data), 0x1337);

  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decrypt_1byte_example_in_handout: output mismatch\n");
    return 1;
  }
  return 0;
}
// output buffer too small
int test_decrypt_output_len_too_small(void) {
  // If output_len is smaller than input_len, decrypt_data should returnwithout writing out-of-bounds

  uint8_t input_data[] = {0x60, 0x5A};   // 2 bytes input
  uint8_t output_data[] = {0xAA};        // only 1 byte output buffer (too small)

  decrypt_data(input_data, sizeof(input_data), output_data, sizeof(output_data), 0x1337);

  // Output should remain unchanged
  if (output_data[0] != 0xAA) {
    printf("FAIL test_decrypt_output_len_too_small: output_data was modified\n");
    return 1;
  }
  return 0;
}

//-------------------------------------
//        DECOMPRESSION TESTS
//--------------------------------------
// a demo dictionary of 16 bytes
static void demo_dictionary(uint8_t dict[DICTIONARY_LENGTH]) {
  for (int i = 0; i < DICTIONARY_LENGTH; i++) {
    dict[i] = (uint8_t)(0x30 + i); // 0x30, 0x31....0x3F
  }
}

int test_decompress_handout_example(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  //compresssed inpput from handout
  uint8_t input_data[] = {0x01, 0x07, 0x42};
  uint8_t output_data[32];
  memset(output_data, 0xAA, sizeof(output_data)); // fill it with junk first

  // run decompression
  size_t out_len = decompress_data(input_data, sizeof(input_data),
                                   output_data, sizeof(output_data),
                                   dict);
  // expected result
  uint8_t expected[] = {0x01, 0x32, 0x32, 0x32, 0x32};

  // check returned length
  if (out_len != sizeof(expected)) {
    printf("FAIL test_decompress_handout_example: out_len got %lu expected %lu\n", (unsigned long)out_len, (unsigned long)sizeof(expected));
    return 1;
  }

  // check bytes
  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decompress_handout_example: output bytes mismatch\n");
    return 1;
  }
  return 0;
}

// literal escape case: input = [0x07, 0x00] output = [0x07]
int test_decompress_literal_escape(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  uint8_t input_data[] = {0x07, 0x00};

  uint8_t output_data[8];
  memset(output_data, 0xAA, sizeof(output_data));

  size_t out_len = decompress_data(input_data, sizeof(input_data),
                                   output_data, sizeof(output_data),
                                   dict);

  uint8_t expected[] = {0x07};

  if (out_len != sizeof(expected)) {
    printf("FAIL test_decompress_literal_escape: out_len got %lu expected %lu\n",
           (unsigned long)out_len, (unsigned long)sizeof(expected));
    return 1;
  }

  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decompress_literal_escape: output bytes mismatch\n");
    return 1;
  }

  return 0;
} 

// last byte as escape byte: input = [0xAA, 0x07] output = [0xAA, 0x07]
int test_decompress_trailing_escape_byte(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  uint8_t input_data[] = {0xAA, 0x07};

  uint8_t output_data[8];
  memset(output_data, 0xAA, sizeof(output_data));

  size_t out_len = decompress_data(input_data, sizeof(input_data),
                                   output_data, sizeof(output_data),
                                   dict);

  uint8_t expected[] = {0xAA, 0x07};

  if (out_len != sizeof(expected)) {
    printf("FAIL test_decompress_trailing_escape_byte: out_len got %lu expected %lu\n",
           (unsigned long)out_len, (unsigned long)sizeof(expected));
    return 1;
  }

  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decompress_trailing_escape_byte: output bytes mismatch\n");
    return 1;
  }

  return 0;
}

// mixed literals + one run
int test_decompress_mixed_literals_and_run(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  uint8_t input_data[] = {0x10, 0x07, 0x21, 0x20};

  uint8_t output_data[16];
  memset(output_data, 0xAA, sizeof(output_data));

  size_t out_len = decompress_data(input_data, sizeof(input_data),
                                   output_data, sizeof(output_data),
                                   dict);

  uint8_t expected[] = {0x10, 0x31, 0x31, 0x20};

  if (out_len != sizeof(expected)) {
    printf("FAIL test_decompress_mixed_literals_and_run: out_len got %lu expected %lu\n",
           (unsigned long)out_len, (unsigned long)sizeof(expected));
    return 1;
  }

  if (memcmp(output_data, expected, sizeof(expected)) != 0) {
    printf("FAIL test_decompress_mixed_literals_and_run: output bytes mismatch\n");
    return 1;
  }

  return 0;
}

// repeat-count = 0 => write nothing
int test_decompress_repeat_count_zero(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  uint8_t input_data[] = {0x07, 0x02};

  uint8_t output_data[8];
  memset(output_data, 0xAA, sizeof(output_data));

  size_t out_len = decompress_data(input_data, sizeof(input_data),
                                   output_data, sizeof(output_data),
                                   dict);

  // Expect nothing written
  if (out_len != 0) {
    printf("FAIL test_decompress_repeat_count_zero: out_len got %lu expected 0\n",
           (unsigned long)out_len);
    return 1;
  }

  return 0;
}
// empty input => decompress writes nothing
int test_decompress_empty_input(void) {
  uint8_t dict[DICTIONARY_LENGTH];
  demo_dictionary(dict);

  uint8_t dummy = 0xFF;        // dummy byte
  uint8_t output_data[8];
  memset(output_data, 0xAA, sizeof(output_data));

  size_t out_len = decompress_data(&dummy, 0,
                                   output_data, sizeof(output_data),
                                   dict);

  if (out_len != 0) {
    printf("FAIL test_decompress_empty_input: out_len got %lu expected 0\n",
           (unsigned long)out_len);
    return 1;
  }

  return 0;
}

//----------------------------------------------
//          TWO-STREAM FLOATING POINT TESTS
//----------------------------------------------
// Helper: compare 4 bytes and print them if mismatch
static int assert_4bytes_eq(const uint8_t* got, const uint8_t* exp, const char* msg) {
  // memcmp == 0 means identical
  if (memcmp(got, exp, 4) != 0) {
    printf("FAIL %s: got [%02X %02X %02X %02X] expected [%02X %02X %02X %02X]\n",
           msg,
           got[0], got[1], got[2], got[3],
           exp[0], exp[1], exp[2], exp[3]);
    return 1;
  }
  return 0;
}

//Handout example: float 300.0 = 0x43960000
// Little-endian bytes of the final float: [00 00 96 43]
// signfrac = 0x160000 -> bytes [00 00 16]
// exp      = 0x87
int test_join_float_single_300(void) {
  // signfrac stream holds 3 bytes per float (little-endian)
  uint8_t signfrac[] = { 0x00, 0x00, 0x16 };

  // exponent stream holds 1 byte per float
  uint8_t exp[] = { 0x87 };

  // output must hold 4 bytes per float
  uint8_t out[4] = { 0xAA, 0xAA, 0xAA, 0xAA }; // fill so we can detect writes

  join_float_array(signfrac, sizeof(signfrac), exp, sizeof(exp), out, sizeof(out));

  // Expected little-endian float bytes for 0x43960000
  uint8_t expected[4] = { 0x00, 0x00, 0x96, 0x43 };

  return assert_4bytes_eq(out, expected, "test_join_float_single_300");
}

//float bits: 0xDEADBEEF
// Little-endian bytes should be: [EF BE AD DE]
//   stream1(signfrac) = 0xAD BEEF (24 bits) -> little-endian bytes [EF BE AD]
//   stream2(exp)      = 0xBD
int test_join_float_single_deadbeef(void) {
  uint8_t signfrac[] = { 0xEF, 0xBE, 0xAD }; // 0xAD BEEF as 3 bytes little-endian
  uint8_t exp[]      = { 0xBD };

  uint8_t out[4] = { 0xAA, 0xAA, 0xAA, 0xAA };

  join_float_array(signfrac, sizeof(signfrac), exp, sizeof(exp), out, sizeof(out));

  // 0xDEADBEEF in little-endian is EF BE AD DE
  uint8_t expected[4] = { 0xEF, 0xBE, 0xAD, 0xDE };

  return assert_4bytes_eq(out, expected, "test_join_float_single_deadbeef");
}
// n = 0 (empty streams)
// We expect: function does nothing,
int test_join_float_empty(void) {
  uint8_t out[4] = { 0xAA, 0xAA, 0xAA, 0xAA };

  join_float_array(NULL, 0, NULL, 0, out, sizeof(out));

  // Output should remain unchanged if nothing to process
  uint8_t expected[4] = { 0xAA, 0xAA, 0xAA, 0xAA };
  return assert_4bytes_eq(out, expected, "test_join_float_empty");
}

// length mismatch (signfrac not 3*n or exp not n)
// We expect: function returns without writing
int test_join_float_length_mismatch(void) {
  // signfrac length is 4 (not divisible by 3) => invalid
  uint8_t signfrac[] = { 0x00, 0x00, 0x16, 0xFF };
  uint8_t exp[]      = { 0x87 };

  uint8_t out[4] = { 0xAA, 0xAA, 0xAA, 0xAA };

  join_float_array(signfrac, sizeof(signfrac), exp, sizeof(exp), out, sizeof(out));

  // we should not touch output?
  uint8_t expected[4] = { 0xAA, 0xAA, 0xAA, 0xAA };
  return assert_4bytes_eq(out, expected, "test_join_float_length_mismatch");
}

// output buffer too small
// We expect: function returns without writing
int test_join_float_output_too_small(void) {
  uint8_t signfrac[] = { 0x00, 0x00, 0x16 }; // 1 float
  uint8_t exp[]      = { 0x87 };

  // Output is only 3 bytes, but needs 4
  uint8_t out[3] = { 0xAA, 0xAA, 0xAA };

  join_float_array(signfrac, sizeof(signfrac), exp, sizeof(exp), out, sizeof(out));

  // Output should remain unchanged
  if (out[0] != 0xAA || out[1] != 0xAA || out[2] != 0xAA) {
    printf("FAIL test_join_float_output_too_small: output was modified\n");
    return 1;
  }
  return 0;
}



int main(void) {
  // Test the LFSR implementation
  int result = test_lfsr_step();
  if (result != 0) {
    printf("Error when testing LFSR implementation\n");
    return 1;
  }

  // // TODO - add tests here for other functionality
  // // You can craft arbitrary array data as inputs to the functions
  // // Parsing headers, checksumming, decryption, and decompressing are all testable


// Test checksum implementation
  result = example_test();
  if (result != 0) {
    printf("ERROR: example_test_setup failed\n");
    return 1;
  }
  result = test_checksum_empty();
  if (result != 0) { printf("ERROR: test_checksum_empty failed\n"); return 1; }

  result = test_checksum_single_byte();
  if (result != 0) { printf("ERROR: test_checksum_single_byte failed\n"); return 1; }

  // result = test_checksum_overflow_wrap();
  // if (result != 0) { printf("ERROR: test_checksum_overflow_wrap failed\n"); return 1; }

  // result = test_checksum_pattern_0_to_255();
  // if (result != 0) { printf("ERROR: test_checksum_pattern_0_to_255 failed\n"); return 1; }

  // result = test_checksum_null_len0();
  // if (result != 0) { printf("ERROR: test_checksum_null_len0 failed\n"); return 1; }
  

  // Test parse_header implementation
  result = test_parse_header();
  if (result != 0) { printf("ERROR: test_parse_header failed\n"); return 1; }

  result = test_parse_header_minimal_20();
  if (result != 0) { printf("ERROR: test_parse_header_minimal_20 failed\n"); return 1; }

  result = test_parse_header_checksum_only_22();
  if (result != 0) { printf("ERROR: test_parse_header_checksum_only_22 failed\n"); return 1; }

  result = test_parse_header_compression_only_36();
  if (result != 0) { printf("ERROR: test_parse_header_compression_only_36 failed\n"); return 1; }

  result = test_parse_header_too_short();
  if (result != 0) { printf("ERROR: test_parse_header_too_short failed\n"); return 1; }

  result = test_parse_header_wrong_magic();
  if (result != 0) { printf("ERROR: test_parse_header_wrong_magic failed\n"); return 1; }

  result = test_parse_header_wrong_version();
  if (result != 0) { printf("ERROR: test_parse_header_wrong_version failed\n"); return 1; }

  result = test_parse_header_compressed_but_short();
  if (result != 0) { printf("ERROR: test_parse_header_compressed_but_short failed\n"); return 1; }

  result = test_parse_header_checksummed_but_short();
  if (result != 0) { printf("ERROR: test_parse_header_checksummed_but_short failed\n"); return 1; }


  // Test the decrypt data implementation
  result = test_decrypt_4byte_example_in_handout();
  if (result != 0) { printf("ERROR: test_decrypt_4byte_example_in_handout failed\n"); return 1; }

  result = test_decrypt_1byte_example_in_handout();
  if (result != 0) { printf("ERROR: test_decrypt_1byte_example_in_handout failed\n"); return 1; }

  result = test_decrypt_output_len_too_small();
  if (result != 0) { printf("ERROR: test_decrypt_output_len_too_small failed\n"); return 1; }

  //test decompress
  result = test_decompress_handout_example();
  if (result != 0) { printf("ERROR: test_decompress_handout_example failed\n"); return 1; }

  result = test_decompress_literal_escape();
  if (result != 0) { printf("ERROR: test_decompress_literal_escape failed\n"); return 1; }

  result = test_decompress_trailing_escape_byte();
  if (result != 0) { printf("ERROR: test_decompress_trailing_escape_byte failed\n"); return 1; }

  result = test_decompress_mixed_literals_and_run();
  if (result != 0) { printf("ERROR: test_decompress_mixed_literals_and_run failed\n"); return 1; }

  result = test_decompress_repeat_count_zero();
  if (result != 0) { printf("ERROR: test_decompress_repeat_count_zero failed\n"); return 1; }

  result = test_decompress_empty_input();
  if (result != 0) { printf("ERROR: test_decompress_empty_input failed\n"); return 1; }

  // test two-stream floating point
    result = test_join_float_single_300();
  if (result != 0) { printf("ERROR: test_join_float_single_300 failed\n"); return 1; }

  result = test_join_float_single_deadbeef();
  if (result != 0) { printf("ERROR: test_join_float_single_deadbeef failed\n"); return 1; }

  //result = test_join_float_two_values();
  //if (result != 0) { printf("ERROR: test_join_float_two_values failed\n"); return 1; }

  result = test_join_float_empty();
  if (result != 0) { printf("ERROR: test_join_float_empty failed\n"); return 1; }

  result = test_join_float_length_mismatch();
  if (result != 0) { printf("ERROR: test_join_float_length_mismatch failed\n"); return 1; }

  result = test_join_float_output_too_small();
  if (result != 0) { printf("ERROR: test_join_float_output_too_small failed\n"); return 1; }


  printf("All tests passed successfully!\n");
  return 0;
  
}

