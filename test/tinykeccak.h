#include <stdint.h>
#include <string.h>
/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define decsha3(bits) \
  int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);
