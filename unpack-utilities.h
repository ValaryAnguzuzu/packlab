// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#pragma once

#include <stdbool.h>
#include <stdint.h> // fixed_width ints
#include <stdlib.h> // size_t and malloc

// Definitions
#define MAX_STREAMS       16 // packed file can contain a max of 16 streams
#define HEADER_ALIGN      4096
#define DATA_ALIGN        4096
#define MAX_HEADER_SIZE   (4 + 8 + 8 + 16 + 2) // max possible header size for one stream:
//4 = magic:2+version:1+flags:1;  8 = orig data size; 8 = packed data size; 16 = dict(if compressed); 2 = checksum(if checksum)
// 20 bytes (MIN) to 38 bytes (MAX)
#define DICTIONARY_LENGTH 16 
#define ESCAPE_BYTE       0x07 
#define MAX_RUN_LENGTH    16 // each group of 4 bits can represent 16 distinct values (0–15)


// Struct to hold header configuration data
// The data is parsed from the header and recorded in this struct
    // config struct: represents header info for one stream
typedef struct {
  // whether the header is VALID OR NOT
  // values of other fields are irrelevant if the header isn't valid
  // if true: safe to proceed
  bool is_valid;

  // total length of the header data, not including padding
  // values one of 20, 36, 22 or 38
  size_t header_len;

  // whether the file was compressed
    // if so, set to true ie file must be decompressed
  bool is_compressed;

  // compression dictionary from header
  // (only valid if is_compressed is true)
    // if compressed, copy 16 dic bytes here
  uint8_t dictionary_data[DICTIONARY_LENGTH];

  // whether the file was encrypted
    // if so, set to true ie file must be decrypted
  bool is_encrypted;

  // whether the file was checksummed
    // if so, set to true ie stream should be validated
  bool is_checksummed;

  // expected checksum value from header
  // (only valid if is_checksummed is true)
    // note it is BIG ENDIAN
  uint16_t checksum_value;

  // whether there is a subsequent header
    // true => after this stream there is another header later
    // false => this is the last stream
  bool should_continue;

  // whether this stream is part of a split floating point stream pair
  bool should_float;

  // whether floating point is being handled with 3 streams instead of 2
  bool should_float3;

  // the size of data originally packed into this stream, in bytes
    // size after decrypt/decompress: FINAL OUTPUT SIZE FOR THIS STREAM (little-endian)
  uint64_t orig_data_size;

  // the size of the data in this stream (i.e., after compression), in bytes
    // little-endian
  uint64_t data_size;

} packlab_config_t;


// Prints error message and then exits the program with a return code of one
void error_and_exit(const char* message);

// Allocates `size` bytes of heap data and returns a pointer to it
// Faults and exits the program if malloc fails
void* malloc_and_check(size_t size);

// Parses the header data to determine configuration for the packed file
// Configuration information is written into config
// Any unnecessary fields in config are left untouched
void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config);

// Decompresses input data, creating output data
// Returns the length of valid data inside the output data (<=output_len)
// Expects a previously calculated compression dictionary
// Writes uncompressed data directly into `output_data`
size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data);

// Returns the next LFSR state
// Implemented with a fixed LFSR
// Does not save state internally. To iterate, update as oldstate = lfsr_step(oldstate)
uint16_t lfsr_step(uint16_t oldstate);

// Decrypts input data, creating output data
// Writes decrypted data directly into `output_data`
void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key);

// Calculates a 16-bit checksum value over input data
uint16_t calculate_checksum(uint8_t* input_data, size_t input_len);

// join 2 streams to create a single stream of 32 bit IEEE floats
// one stream consists of sign|fraction (24 bits each), and
// the other stream consists of exp (8 bits each)
// assuming there there are n floats, then
// input_len_bytes_signfrac must be 3*n
// input_len_bytes_exp must be n
// output_len_bytes must be >=4*n
void join_float_array(uint8_t* input_signfrac, size_t input_len_bytes_signfrac,
                      uint8_t* input_exp, size_t input_len_bytes_exp,
                      uint8_t* output_data, size_t output_len_bytes);



// For Extra Credit:
// join 3 streams to create a single stream of 32 bit IEEE floats
// one stream consists of sign (1 bit each),
// another consists of fraction (23 bits each), and
// the last stream consists of exp (8 bits each)
// assuming there there are n floats, then
// input_len_bytes_signfrac must be 3*n
// input_len_bytes_exp must be n
// output_len_bytes must be >=4*n
void join_float_array_three_stream(uint8_t* input_frac,
                                   size_t   input_len_bytes_frac,
                                   uint8_t* input_exp,
                                   size_t   input_len_bytes_exp,
                                   uint8_t* input_sign,
                                   size_t   input_len_bytes_sign,
                                   uint8_t* output_data,
                                   size_t   output_len_bytes);

