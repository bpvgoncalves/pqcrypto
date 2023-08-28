#include <cpp11.hpp>
extern "C" {
#include "kyber/api.h"
}


[[cpp11::register]]
cpp11::integers cpp_decap_kyber512(cpp11::integers secret_key, cpp11::integers cipher_text) {

  uint8_t s_key[pqcrystals_kyber512_SECRETKEYBYTES];
  uint8_t c_text[pqcrystals_kyber512_CIPHERTEXTBYTES];
  uint8_t s_secret[pqcrystals_kyber512_BYTES];

  for(int i = 0; i < pqcrystals_kyber512_SECRETKEYBYTES; ++i) {
    s_key[i] = secret_key[i];
  }
  for(int i = 0; i < pqcrystals_kyber512_CIPHERTEXTBYTES; ++i) {
    c_text[i] = cipher_text[i];
  }

  int result = pqcrystals_kyber512_ref_dec(s_secret, c_text, s_key);

  cpp11::writable::integers shared_secret(pqcrystals_kyber512_BYTES);
  for(int i = 0; i < pqcrystals_kyber512_BYTES; ++i) {
    shared_secret[i] = s_secret[i];
  }

  return shared_secret;
}
