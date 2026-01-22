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
  // checksum included only when is_checksummed? is enabled => unsigned 16-bit big-endian
  // adding the value of every byte in the file to a counter init at 0, and allowing for overflows
    // Start with a 16-bit unsigned counter at 0
    // For each byte in the stream data:
    //   add that byte’s value to the counter
    //   If the sum gets too big for 16 bits:
    //     it wraps around (overflow)

  // if there's no data pointer, we can't read bytes
  if (input_data == NULL) return 0;

  uint16_t checksum = 0;
  for (size_t i = 0; i < input_len; i++) {
    checksum = (uint16_t)(checksum + (uint16_t)input_data[i]); // input data is uint8_t, we cast to uint16_t => 16bits world
  }
  return checksum;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state

  // extract the tagged bits: 
  uint16_t b0 = (oldstate >> 0) & 1u;
  uint16_t b6 = (oldstate >> 6) & 1u;
  uint16_t b9 = (oldstate >> 9) & 1u;
  uint16_t b13 = (oldstate >> 13) & 1u;

  // XOR them to get newbit
  uint16_t newbit = (uint16_t)(b0 ^ b6 ^ b9 ^ b13); // gives 0 or 1

  // right shift oldstate by 1
  uint16_t shifted = (uint16_t)(oldstate >> 1);

  //insert newbit into MSb psn: left shit newbit to create space,  OR newbit with old state
  uint16_t newstate = (uint16_t)((newbit << 15) | shifted);

  // return the next lfsr state
  return newstate;
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in little-endian order
  // Beware: input_data may be an odd number of bytes: XOR with LSB

    //start state = encryption_key
    // for every 2 bytes:
      // Step the LFSR once
      // XOR input at first psn with LSB
      // XOR input at second psn with MSB
    // if one byte remains:
      // step the LFSR once
      // XOR input at first psn with LSB

  // bad pointers
  if (input_data == NULL || output_data == NULL) return;
  
  // we should nevre write past out put data:
  if (output_len < input_len) return;

  // LFSR initial state => encryption key
  uint16_t state = encryption_key;

  // process pairs of bytes
  size_t i = 0;
  while (i + 1 < input_len) {
    // generate next LFSR state
    state = lfsr_step(state);

    // split the 16bit (2bytes) output into LSB -> MSB (1 byte each = 8bits)
    uint8_t key_lo = (uint8_t)(state & 0x00FFu); // LSB
    uint8_t key_hi = (uint8_t)((state >> 8) & 0x00FFu); // MSB


    // XOR the two input bytes with the two key bytes (LSB -> MSB) and write the results to output data
    output_data[i]     = (uint8_t)(input_data[i] ^ key_lo); // first input byte uses LSB key
    output_data[i + 1] = (uint8_t)(input_data[i+1] ^ key_hi); // second input byte uses MSB key

    // advance by 2 bytes:
    i += 2;
  }

  // if theres one leftover byte; xor with lsb
  if (i < input_len) {
    // genrate next LFSR state for this last byte
    state = lfsr_step(state);

    // use LSB only
    uint8_t key_lo = (uint8_t)(state & 0x00FFu); // LSB

    // XOR
    output_data[i] = (uint8_t)(input_data[i] ^ key_lo);

  }

}

// Decompresses input data, creating output data
// Returns the length of valid data inside the output data (<=output_len)
// Expects a previously calculated compression dictionary
// Writes uncompressed data directly into `output_data`
size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data

  // we have a stream of compressed bytes(input_data); goal os to rebuild the original bytes(output_data) excatly
  // in input_data each byte is either:
    // a normal literal byte => this exact byte is part of the orig file
    // special byte: 0x07 => check the next byte: 
      // byte after is 0x00 => not a compression: 0x07 0x00 = 0x07
      // byte after is not 0x00 => bits 0-3: dict index (0-15) => bits 4-7: repeat count (0-15)

    // if input[i] != 0x07: copy it to output, i++
    // else (inout[i] == 0x07):
      // if i == input_len -1 (last byte): output literal, i++
      // else:
        // decode repeat-count and dict-index
        // output repeated bytes, from index dict-index; repeat-count times
        // i += 2
      // track output_len so we dont write beyond it
  if (input_data == NULL || output_data == NULL || dictionary_data == NULL){
    return 0;}
  size_t out_pos = 0;

  // walk through output buffer
  size_t i = 0;
  while (i < input_len) {
    // read the curr input byte
    uint8_t b = input_data[i];

    // normal case
    if (b != ESCAPE_BYTE) {
      // don't write past buffer
      if (out_pos >= output_len) {
        return out_pos;
      }
      // copy literal byte directly to output
      output_data[out_pos] = b;
      out_pos++;

      // move to next input byte
      i++;
      continue;
    }

    // if we get here; escape byte = 0x07
    // if the escape byte is the very last byte, treat as a normal literal
    if (i == input_len - 1) {
      if (out_pos >= output_len) {
        return out_pos;
      }

      output_data[out_pos] = ESCAPE_BYTE;
      out_pos++;
      i++; // this is the last byte
      continue;
    }

    // otherwise THERE IS a second byte
    uint8_t code = input_data[i+1];

    // case: [0x07, 0x00]
    if (code == 0x00){
      if (out_pos >= output_len) {
        return out_pos;
      }

      output_data[out_pos] = ESCAPE_BYTE;
      out_pos++;

      i += 2; // pass both input bytes
      continue;
    }

    // compressed run encoding is [0x07, code]
      // low 4 bits = dict-index
      // high 4 bits = repeat-count
    uint8_t dict_index = (uint8_t)(code & 0x0Fu); // extract the low 4 bits
    uint8_t repeat_count = (uint8_t)((code >> 4) & 0x0Fu); // extract the upper 4  bits

    // get the byte to repeat from dictionary
    uint8_t value_to_repeat = dictionary_data[dict_index];

    // write this value to output repeat-count times
    for (uint8_t r=0; r<repeat_count; r++) {
      if (out_pos >= output_len){
        return out_pos;
      }

      output_data[out_pos] = value_to_repeat;
      out_pos++;
    }

    // pass both input bytes 
    i += 2;

  }

  // return how many bytes wrote to output-data

  return out_pos;
}

void join_float_array(uint8_t* input_signfrac, size_t input_len_bytes_signfrac,
                      uint8_t* input_exp, size_t input_len_bytes_exp,
                      uint8_t* output_data, size_t output_len_bytes) {

  // TODO
  // Combine two streams of bytes, one with signfrac data and one with exp data,
  // into one output stream of floating point data
  // Output bytes are in little-endian order
  // when float? is true:
    // for each float pack:
      // takes the sigh bit takes the 23 bit frac => combine them into 24 bits and store them into  sign-frac 
      // takes the 8bit exponent => stores it in exp stream
  // for float i:
    // read 3 bytes from sign-frac
    // read 1 byte from exp
    // reconstruct 32 bit value [sign-frac(24bits)][exponent(8bits)]
    // write out float in little endian
      // stream length must match: sig-frac-bytes = exp-bytes * 3
      // sign-frac[0,1,2] pairs with exp[0]
      // sign-frac[3,4,5] pairs with exp[1]
      // little endian for sign-frac and output float

  // out[0] = fraction bits 0..7     = signfrac[0]
  //out[1] = fraction bits 8..15    = signfrac[1]
  //out[2] = fraction bits 16..22   (7 bits)  + exponent bit0 as the MSB
  //out[3] = exponent bits 1..7     (7 bits)  + sign bit as the MSB

  // no output data
  if (output_data == NULL){
    return; // nowhere to write
  }
  // if both inputs are empty, do nothing
  if (input_len_bytes_signfrac == 0 && input_len_bytes_exp == 0) {
    return;
  }

  // If one input pointer is NULL but length is non-zero, we can't read safely
  if (input_signfrac == NULL || input_exp == NULL) {
    return;
  }

  // valid lengths: ach float needs: signfrac: 3 bytes; exp: 1 byte
  // So signfrac length MUST be divisible by 3, and exp length must match float count
  if (input_len_bytes_signfrac % 3 != 0) {
    return; // invalid signfrac stream length
  }

  // Number of floats is determined by signfrac length
  size_t n_floats = input_len_bytes_signfrac / 3;

  // exp must have exactly 1 byte per float
  if (input_len_bytes_exp != n_floats) {
    return; // streams disagree on float count
  }

  // Output must have at least 4 bytes per float
  if (output_len_bytes < 4 * n_floats) {
    return; // not enough space to write output floats
  }

  // join each float
  for (size_t i = 0; i < n_floats; i++) {
    // Read the 3 signfrac bytes for float i
      // [ sign ][ exp7 exp6 exp5 exp4 exp3 exp2 exp1 exp0 ][ frac22 ... frac0 ]
      // signfrac is little-endian:
        // byte0 = frac0  frac1  frac2  frac3  frac4  frac5  frac6  frac7 (lowest adrress)
        // byte1 = frac0  frac1  frac2  frac3  frac4  frac5  frac6  frac7
        // byte2 = frac16 frac17 frac18 frac19 frac20 frac21 frac22 exp0
        // byte3 = exp1 exp2 exp3 exp4 exp5 exp6 exp7 sign (highest address)
      // out[0] = fraction bits 0..7     = signfrac[0]
      // out[1] = fraction bits 8..15    = signfrac[1]
      // out[2] = fraction bits 16..22 + exponent bit0
      // out[3] = exponent bits 1..7 + sign bit

    uint8_t b0 = input_signfrac[3 * i + 0];
    uint8_t b1 = input_signfrac[3 * i + 1];
    uint8_t b2 = input_signfrac[3 * i + 2];

    // Read exponent byte for float i
    uint8_t exp = input_exp[i];

    //Extract sign bit (1 bit) from b2's MSB: sign = 0 or 1
    uint8_t sign = (uint8_t)((b2 >> 7) & 0x01u);

    // Extract the top 7 fraction bits from b2 (bits0..6)
    uint8_t frac_hi7 = (uint8_t)(b2 & 0x7Fu);

    // final IEEE-754 float bytes in little-endian order:
      // output[0] = b0
      // output[1] = b1
      //
      // output[2]:
          // bits0..6 = frac_hi7
          // bit7     = exponent bit0
      //
      // output[3]:
          // bits0..6 = exponent bits1..7  (that's exp >> 1)
          // bit7     = sign

    // exponent bit0 is the least significant bit of exp
    uint8_t exp_bit0 = (uint8_t)(exp & 0x01u);

    // exponent bits1..7 become a 7-bit value (exp shifted right by 1)
    uint8_t exp_hi7 = (uint8_t)(exp >> 1);

    // Construct byte2 (fraction hi7 + exponent bit0 in MSB)
    uint8_t out2 = (uint8_t)(frac_hi7 | (uint8_t)(exp_bit0 << 7));

    // Construct byte3 (exponent hi7 + sign in MSB)
    uint8_t out3 = (uint8_t)(exp_hi7 | (uint8_t)(sign << 7));

  // Write the 4 bytes into output
    output_data[4 * i + 0] = b0;
    output_data[4 * i + 1] = b1;
    output_data[4 * i + 2] = out2;
    output_data[4 * i + 3] = out3;
  }

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

