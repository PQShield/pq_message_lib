#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * All possible algorithms that can be requested.
 */
typedef enum {
  NoAlgorithm,
  FRODO640__ECDHp256,
  FRODO640,
  FRODO976__ECDHp384,
  FRODO976,
  FRODO1344__ECDHp521,
  FRODO1344,
  NTRU_HRSS_701,
  NTRU_HRSS_701__ECDHp256,
  NTRU_HPS_2048509,
  NTRU_HPS_2048509__ECDHp256,
  RND5_1CCA_5D,
  RND5_1CCA_5D__ECDHp256,
  RND5_3CCA_5D,
  RND5_3CCA_5D__ECDHp384,
  RND5_5CCA_5D,
  RND5_5CCA_5D__ECDHp521,
  KYBER_512,
  KYBER_512__ECDHp256,
  KYBER_768,
  KYBER_768__ECDHp384,
  KYBER_1024,
  KYBER_1024__ECDHp521,
  SABER_LIGHT,
  SABER_LIGHT__ECDHp256,
  SABER,
  SABER__ECDHp384,
  SABER_FIRE,
  SABER_FIRE__ECDHp521,
} Algorithm;

/**
 * All possible operations that can be requested.
 */
typedef enum {
  NoOperation,
  KeypairGeneration,
  Encapsulation,
  Decapsulation,
} Operation;

/**
 * Header that describes the response sent.
 * # Explanation of the header
 * - version is used for compatibility reasons. Typically there is no need to do anything with this
 *   as pq_message_lib deals with version internally.
 * - identifier is used so that the receiver of the `ResponseHeader` can link it back to the original request.
 * - success indicates there was a failure or not. 0 means success while anything else is a failure.
 *   Note that the data_len field will always be 0 when there was a failure.
 * - data_len describes the length of the upcoming data that belongs to this `ResponseHeader`. The data after that
 *   will belong to a new `ResponseHeader`.
 */
typedef struct {
  uint8_t version;
  uint64_t identifier;
  int8_t success;
  uint32_t data_len;
} ResponseHeader;

/**
 * Convenience struct to allow response body to be stored together together with the header.
 */
typedef struct {
  ResponseHeader header;
  const unsigned char *body;
} Response;

/**
 * Given a pointer will return a `ResponseHeader`. This header can be used to determine how many bytes
 * of data are coming up.
 * # Returns
 * 0 on success.
 * -1 when a null pointer was passed in.
 * -2 for when the header will not fit in memory due to architecture.
 * -3 for deserialization failure.
 * -4 for mismatch of version in header.
 * # Safety
 * Unsafe because there is no absolute guarantee we don't get a pointer handed somewhere
 * in program space that happens to deserialize succesfully to a ResponseHeader.
 * When used in combination with `get_serialized_response_header_size` this function
 * will be able to safely and correctly deserialize a response header.
 */
int16_t deserialize_response_header(const unsigned char *response_data,
                                    ResponseHeader *response_header);

/**
 * Given a pointer of a buffer which contains two data fields it will set entry1 and entry2 pointers to those locations
 * within the buffer. Additionally it will set the length appropriately.
 * # Returns
 * 0 on success.
 * -1 when data pointer was null.
 * -2 when entry1_length pointer was null.
 * -3 when entry2_length pointer was null.
 * -4 when entry1 pointer was null.
 * -5 when entry2 pointer was null.
 * -6 or -7 if parsing the lengths is unsuccessful
 * -8 if the provided data would cause an out of bounds access
 * # Safety
 * This function does extensive checking on null pointers and checks whether
 * the lengths provided in the structured data would write past the end of `data`.
 * Having said that, if the caller inputs an invalid `data_size` there is no way
 * for this function to ever realize this; this will not happen unless the caller
 * has a bug since the header will inform the caller how large the buffer should be.
 */
int16_t destructure_two_entries(const unsigned char *data,
                                size_t data_size,
                                size_t *entry1_length,
                                size_t *entry2_length,
                                const unsigned char **entry1,
                                const unsigned char **entry2);

/**
 * Returns the size needed for the buffer where the serialized request header will be stored.
 * Will evaluate only when used for the first time.
 */
uint64_t get_serialized_request_header_size(void);

/**
 * Returns the size needed for the buffer where the serialized response header will be stored.
 * Will evaluate only when used for the first time.
 */
uint64_t get_serialized_response_header_size(void);

/**
 * Receive a serialized header. Simply attach the raw bytes behind this serialized header when sending
 * over a channel.
 * # Returns
 * 0 on success, -1 on serialization failure.
 * # Safety
 * Ensure that `target_buffer` is large enough before executing this function.
 */
int16_t serialize_request_header(unsigned char *target_buffer,
                                 size_t target_buffer_len,
                                 uint64_t identifier,
                                 uint32_t data_len,
                                 Algorithm algorithm,
                                 Operation operation);

/**
 * Given two entries and their length this function will put them back-to-back into data with length included.
 * # Returns
 * 0 on success.
 * -1 when data was a null pointer.
 * -2 when entry1 was a null pointer.
 * -3 when entry2 was a null pointer.
 * # Safety
 * If entry1_length or entry2_length are not appropriate (too long for example) then an out of bounds
 * access will occur; this is a bug introduced by the caller. When used in combination with the
 * `structure_two_entries_length` function this will never occur.
 */
int16_t structure_two_entries(unsigned char *data,
                              size_t entry1_length,
                              size_t entry2_length,
                              const unsigned char *entry1,
                              const unsigned char *entry2);

/**
 * Given the length of two entries returns the length of the buffer required to fit both entries including their lengths.
 */
size_t structure_two_entries_length(size_t entry1_length,
                                    size_t entry2_length);
