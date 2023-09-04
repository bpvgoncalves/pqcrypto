#include <cpp11.hpp>
extern "C" {
  #include "dilithium/api.h"
}

[[cpp11::register]]
cpp11::integers cpp_sign_dilithium(cpp11::integers message, cpp11::integers private_key) {

  size_t msg_len = message.size();
  int pk_len = private_key.size();
  size_t cr_bytes = 0;
  size_t algo = 0;

  switch (pk_len) {
    case pqcrystals_dilithium2_SECRETKEYBYTES:
      cr_bytes = pqcrystals_dilithium2_BYTES;
      algo = 2;
      break;

    case pqcrystals_dilithium3_SECRETKEYBYTES:
      cr_bytes = pqcrystals_dilithium3_BYTES;
      algo = 3;
      break;

    case pqcrystals_dilithium5_SECRETKEYBYTES:
      cr_bytes = pqcrystals_dilithium5_BYTES;
      algo = 5;
      break;

    default:
      cpp11::stop("Wrong 'private key' lenght.");
      break;
  }

  uint8_t sign[cr_bytes];
  size_t * sign_len;

  uint8_t msg[msg_len];
  for(size_t i = 0; i < msg_len; ++i) {
    msg[i] = message[i];
  }

  uint8_t prvt_k[pk_len];
  for(int i = 0; i < pk_len; ++i) {
    prvt_k[i] = private_key[i];
  }

  int ret;
  switch (algo) {
    case 2:
      ret = pqcrystals_dilithium2_ref_signature(sign, sign_len, msg, msg_len, prvt_k);
      break;
    case 3:
      ret = pqcrystals_dilithium3_ref_signature(sign, sign_len, msg, msg_len, prvt_k);
      break;
    case 5:
      ret = pqcrystals_dilithium5_ref_signature(sign, sign_len, msg, msg_len, prvt_k);
      break;
  }

  cpp11::writable::integers signature(*sign_len);
  for(size_t i = 0; i < *sign_len; ++i) {
    signature[i] = sign[i];
  }

  return signature;
}
