// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {
  //input:
    //input_data: the raw header bytes => a pointer to the first byte of the header we want to interpret
    //input_len: how many of those bytes are valid to read => we are only allowed to access bytes up to input_data[input_len-1]
  // output: config: where the decoded meaning goes

  // TODO
  // Validate the header and set configurations based on it
  // Look at unpack-utilities.h to see what the fields of config are
  // Set the is_valid field of config to false if the header is invalid
  // or input_len (length of the input_data) is shorter than expected

  // magic bytes: always = 0x0213 => first 2 BYTES (B-E): offset 0 and 1
  // vresion: always = 0x03 => next 1 BYTE: offset 2
  // FLAGS: => next 1 BYTE => map it to 7 BIT flag-fields: offset 3
    // minimum len of header = 20 BYTES: 0 flags 
    // maximun le of header = 38 BYTES: flags included
      // no compression/checksum: header_len = 20 + 0 + 0 = 20 BYTES (min)
      // if compression only: header_len = 20 + 16 bytes (dict val) = 36 BYTES
      // if checksummed only: header_len = 20 + 2 bytes (16-bits B-E checksum val) = 22 BYTES
      // if compression + checksum: header_len = 20 + 16 + 2 = 38 BYTES (max)
  // original file length: 8 BYTES (L-E): offset 4 - 11
  // data stream length: 8 BYTES (L-E): offset 12 - 19


  if (config == NULL) return;
  // default to invalid unless we prove anything is correct
  config->is_valid = false;
  if (input_data == NULL) return;

  // minimum header
  const size_t MIN_HEADER_LEN = 4 + 8 + 8;
  if (input_len < MIN_HEADER_LEN) {
    return; // not enough bytes to read the required fields
  }

        // MAGIC BYTES + VERSION
  // verify the magic: = 16 BITS (BE: input_data[0] = MSB,  input_data[1] = LSB)
  uint16_t magic = (uint16_t)((uint16_t)input_data[0] << 8 | (uint16_t)input_data[1]);

  // verify version: = 8 BITS
  uint8_t version = input_data[2];

  if (magic != 0x0213) {
    return;
  }
  if (version != 0x03) {
    return;
  }


          // FLAGS: 8 BITS
  uint8_t flags = input_data[3];
  // Check which options are set in Flags: shift right then & with 1
  // bit 7: compressed?
  config->is_compressed = ((flags >> 7) & 1u) ? true : false;
  // bit 6: encrypted?
  config->is_encrypted = ((flags >> 6) & 1u) ? true : false;
  // bit 5: checksummed?
  config->is_checksummed = ((flags >> 5) & 1u) ? true : false;
  // bit 4: continuation?
  config->should_continue = ((flags >> 4) & 1u) ? true : false;
  // bit 3: floats?
  config->should_float = ((flags >> 3) & 1u) ? true : false;
  // bit 2: float3?
  config->should_float3 = ((flags >> 2) & 1u) ? true : false;
  // bit 1 and 0 unused

  //determine how many more bytes need to be read from the header
  // base header = 20bytes
  size_t header_len = MIN_HEADER_LEN;
  
  //if compressed? + 16bytes
  if (config->is_compressed) {
    header_len += DICTIONARY_LENGTH;
  }

  //if cheksummed? + 2 bytes
  if (config->is_checksummed) {
    header_len += 2;
  }

  // If we weren't given enough bytes to cover the computed header_len, it's invalid
  if (input_len < header_len) {
    return;
  }

  
  // Record the total length of header data based on the configurations (does not include padding)
  config->header_len = header_len;


  // length of the original data: 64 bytes, little endian
  // original data size: offset 4-11
  uint64_t orig_size = 0;
  for (int i = 0; i < 8; i++) {
    //take each 1byte and left shift to put it in the correct posn wrt Little Endian; and update orig by ORing the results
    orig_size |= ((uint64_t)input_data[4 + i]) << (8*i);
  }
  config->orig_data_size = orig_size;

  // length of this stream: 64 bytes, little endian
  // offset 12-19
  uint64_t packed_len = 0;
  for (int i = 0; i < 8; i++) {
    packed_len |= ((uint64_t)input_data[12 + i]) << (8 * i);
  }
  config->data_size = packed_len;

// Pull out the compression dictionary for this stream if Compression? is enabled
// dict starts immediately after the minimum 20 bytes: offset 20-36
size_t offset = MIN_HEADER_LEN;
if (config->is_compressed) {
  // copy 16 dic bytes here
  for (int i = 0; i < DICTIONARY_LENGTH; i++) {
    config->dictionary_data[i] = input_data[offset + (size_t)i];
  }
  // after for loop, move past dictionary
  offset += DICTIONARY_LENGTH;
}

// Pull out the checksum value for this stream if Checksummed? is enabled
// checksum = 16bit unsigned = 2bytes BE
// offset: 37-38
if (config->is_checksummed) {
  uint16_t csum = (uint16_t)((uint16_t)input_data[offset] << 8) | (uint16_t)input_data[offset + 1];

  config->checksum_value = csum;
  offset += 2;
}
// done decoding: set header as valid:
config->is_valid = true;
}



uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {

  // TODO
  // Calculate a checksum over input_data
  // Return the checksum value

  return 0;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state

  return 0;
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in little-endian order
  // Beware: input_data may be an odd number of bytes

}

size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data

  return 0;
}

void join_float_array(uint8_t* input_signfrac, size_t input_len_bytes_signfrac,
                      uint8_t* input_exp, size_t input_len_bytes_exp,
                      uint8_t* output_data, size_t output_len_bytes) {

  // TODO
  // Combine two streams of bytes, one with signfrac data and one with exp data,
  // into one output stream of floating point data
  // Output bytes are in little-endian order

}
/* End of mandatory implementation. */

/* Extra credit */
void join_float_array_three_stream(uint8_t* input_frac,
                                   size_t   input_len_bytes_frac,
                                   uint8_t* input_exp,
                                   size_t   input_len_bytes_exp,
                                   uint8_t* input_sign,
                                   size_t   input_len_bytes_sign,
                                   uint8_t* output_data,
                                   size_t   output_len_bytes) {

  // TODO
  // Combine three streams of bytes, one with frac data, one with exp data,
  // and one with sign data, into one output stream of floating point data
  // Output bytes are in little-endian order

}

