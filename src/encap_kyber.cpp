#include <cpp11.hpp>
extern "C" {
  #include "kyber/api.h"
}


[[cpp11::register]]
cpp11::list cpp_encap_kyber512(cpp11::integers pub_key) {

  uint8_t c_text[pqcrystals_kyber512_CIPHERTEXTBYTES];
  uint8_t s_secret[pqcrystals_kyber512_BYTES];
  uint8_t p_key[pqcrystals_kyber512_PUBLICKEYBYTES];

  for(int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; ++i) {
    p_key[i] = pub_key[i];
  }
  int result = pqcrystals_kyber512_ref_enc(c_text, s_secret, p_key);

  cpp11::writable::integers cipher_text(pqcrystals_kyber512_CIPHERTEXTBYTES);
  for(int i = 0; i < pqcrystals_kyber512_CIPHERTEXTBYTES; ++i) {
    cipher_text[i] = c_text[i];
  }

  cpp11::writable::integers shared_secret(pqcrystals_kyber512_BYTES);
  for(int i = 0; i < pqcrystals_kyber512_BYTES; ++i) {
    shared_secret[i] = s_secret[i];
  }

  return cpp11::writable::list{cipher_text, shared_secret};
}
