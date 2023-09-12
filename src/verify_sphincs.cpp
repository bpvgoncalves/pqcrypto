#include <cpp11.hpp>
extern "C" {
  #include "sphincs/api.h"
}

[[cpp11::register]]
int cpp_verify_sphincs_shake(cpp11::raws signature, cpp11::raws message, cpp11::raws public_key) {

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
  case SPX_SHAKE128S_CRYPTO_BYTES:
    result = SPX_SHAKE128S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHAKE128F_CRYPTO_BYTES:
    result = SPX_SHAKE128F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHAKE192S_CRYPTO_BYTES:
    result = SPX_SHAKE192S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHAKE192F_CRYPTO_BYTES:
    result = SPX_SHAKE192F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHAKE256S_CRYPTO_BYTES:
    result = SPX_SHAKE256S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHAKE256F_CRYPTO_BYTES:
    result = SPX_SHAKE256F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
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

[[cpp11::register]]
int cpp_verify_sphincs_sha2(cpp11::raws signature, cpp11::raws message, cpp11::raws public_key) {

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
  case SPX_SHA128S_CRYPTO_BYTES:
    result = SPX_SHA128S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHA128F_CRYPTO_BYTES:
    result = SPX_SHA128F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHA192S_CRYPTO_BYTES:
    result = SPX_SHA192S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHA192F_CRYPTO_BYTES:
    result = SPX_SHA192F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHA256S_CRYPTO_BYTES:
    result = SPX_SHA256S_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
    break;

  case SPX_SHA256F_CRYPTO_BYTES:
    result = SPX_SHA256F_crypto_sign_verify(sign, sign_len, msg, msg_len, pub_k);
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
