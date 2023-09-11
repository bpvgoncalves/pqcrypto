#include <cpp11.hpp>
extern "C" {
  #include "sphincs/api.h"
}

[[cpp11::register]]
cpp11::raws cpp_sign_sphincs_shake(cpp11::raws message,
                                   cpp11::raws private_key,
                                   cpp11::logicals is_fast) {

  size_t msg_len = message.size();
  uint8_t* msg = new uint8_t[msg_len];
  for(size_t i = 0; i < msg_len; ++i) {
    msg[i] = message[i];
  }

  int pk_len = private_key.size();
  uint8_t* prvt_k = new uint8_t[pk_len];
  for(int i = 0; i < pk_len; ++i) {
    prvt_k[i] = private_key[i];
  }

  uint8_t* sign;
  size_t sign_len;
  int result;

  switch (pk_len) {

    case 64:
      if (is_fast) {
        sign = new uint8_t[SPX_SHAKE128F_CRYPTO_BYTES];
        result = SPX_SHAKE128F_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      } else {
        sign = new uint8_t[SPX_SHAKE128S_CRYPTO_BYTES];
        result = SPX_SHAKE128S_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      }
      break;

    case 96:
      if (is_fast) {
        sign = new uint8_t[SPX_SHAKE192F_CRYPTO_BYTES];
        result = SPX_SHAKE192F_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      } else {
        sign = new uint8_t[SPX_SHAKE192S_CRYPTO_BYTES];
        result = SPX_SHAKE192S_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      }
      break;

    case 128:
      if (is_fast) {
        sign = new uint8_t[SPX_SHAKE256F_CRYPTO_BYTES];
        result = SPX_SHAKE256F_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      } else {
        sign = new uint8_t[SPX_SHAKE256S_CRYPTO_BYTES];
        result = SPX_SHAKE256S_crypto_sign_signature(sign, &sign_len, msg, msg_len, prvt_k);
      }
      break;
  }

  if (result != 0) {
      cpp11::stop("Something went wrong with the signature generation.");
  }

  cpp11::writable::raws signature(sign_len);
  for(size_t i = 0; i < sign_len; ++i) {
      signature[i] = sign[i];
  }

  delete[] msg;
  delete[] prvt_k;
  delete[] sign;
  return signature;
}
