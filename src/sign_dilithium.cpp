#include <cpp11.hpp>
extern "C" {
  #include "dilithium/api.h"
}

[[cpp11::register]]
cpp11::raws cpp_sign_dilithium(cpp11::raws message, cpp11::raws private_key) {

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
  }

  uint8_t* sign = new uint8_t[cr_bytes];
  size_t sign_len;

  uint8_t* msg = new uint8_t[msg_len];
  for(size_t i = 0; i < msg_len; ++i) {
    msg[i] = message[i];
  }

  uint8_t* prvt_k = new uint8_t[pk_len];
  for(int i = 0; i < pk_len; ++i) {
    prvt_k[i] = private_key[i];
  }

  int result;
  switch (algo) {
    case 2:
      result = pqcrystals_dilithium2_ref_signature(sign, &sign_len, msg, msg_len, prvt_k);
      break;
    case 3:
      result = pqcrystals_dilithium3_ref_signature(sign, &sign_len, msg, msg_len, prvt_k);
      break;
    case 5:
      result = pqcrystals_dilithium5_ref_signature(sign, &sign_len, msg, msg_len, prvt_k);
      break;
  }
  if (result != 0) {
    cpp11::stop("Something went wrong with the signature generation.");
  }

  cpp11::writable::raws signature(sign_len);
  for(size_t i = 0; i < sign_len; ++i) {
    signature[i] = sign[i];
  }

  delete[] sign;
  delete[] msg;
  delete[] prvt_k;
  return signature;
}
