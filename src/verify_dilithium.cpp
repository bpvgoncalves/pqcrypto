#include <cpp11.hpp>
extern "C" {
  #include "dilithium/api.h"
}

[[cpp11::register]]
int cpp_verify_dilithium(cpp11::integers signature,
                         cpp11::integers message,
                         cpp11::integers public_key) {

  size_t sign_len = signature.size();
  uint8_t* sign = new uint8_t[sign_len];
  for(size_t i = 0; i < sign_len; ++i) {
    sign[i] = signature[i];
  }

  size_t msg_len = message.size();
  uint8_t* msg = new uint8_t[msg_len];
  for(size_t i = 0; i < msg_len; ++i) {
    msg[i] = message[i];
  }

  int pk_len = public_key.size();
  uint8_t* pub_k = new uint8_t[pk_len];
  for(int i = 0; i < pk_len; ++i) {
    pub_k[i] = public_key[i];
  }

  int result;
  switch (sign_len) {
  case pqcrystals_dilithium2_BYTES:
    result = pqcrystals_dilithium2_ref_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case pqcrystals_dilithium3_BYTES:
    result = pqcrystals_dilithium3_ref_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case pqcrystals_dilithium5_BYTES:
    result = pqcrystals_dilithium5_ref_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  default:
    cpp11::stop("Wrong 'signature' length.");
    break;
  }

  delete[] sign;
  delete[] msg;
  delete[] pub_k;
  return result;
}
