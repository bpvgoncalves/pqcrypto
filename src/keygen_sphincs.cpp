#include <cpp11.hpp>
extern "C" {
  #include "sphincs/api.h"
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake128s() {

  uint8_t secretkey[SPX_SHAKE128S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE128S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE128S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE128S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE128S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE128S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE128S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake128f() {

  uint8_t secretkey[SPX_SHAKE128F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE128F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE128F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE128F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE128F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE128F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE128F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake192s() {

  uint8_t secretkey[SPX_SHAKE192S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE192S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE192S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE192S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE192S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE192S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE192S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake192f() {

  uint8_t secretkey[SPX_SHAKE192F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE192F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE192F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE192F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE192F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE192F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE192F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake256s() {

  uint8_t secretkey[SPX_SHAKE256S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE256S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE256S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE256S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE256S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE256S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE256S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincsshake256f() {

  uint8_t secretkey[SPX_SHAKE256F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHAKE256F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHAKE256F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHAKE256F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHAKE256F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHAKE256F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHAKE256F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha128s() {

  uint8_t secretkey[SPX_SHA128S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA128S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA128S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA128S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA128S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA128S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA128S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha128f() {

  uint8_t secretkey[SPX_SHA128F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA128F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA128F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA128F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA128F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA128F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA128F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha192s() {

  uint8_t secretkey[SPX_SHA192S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA192S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA192S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA192S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA192S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA192S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA192S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha192f() {

  uint8_t secretkey[SPX_SHA192F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA192F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA192F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA192F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA192F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA192F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA192F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha256s() {

  uint8_t secretkey[SPX_SHA256S_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA256S_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA256S_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA256S_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA256S_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA256S_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA256S_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_sphincssha256f() {

  uint8_t secretkey[SPX_SHA256F_CRYPTO_SECRETKEYBYTES];
  uint8_t publickey[SPX_SHA256F_CRYPTO_PUBLICKEYBYTES];
  int result = SPX_SHA256F_crypto_sign_keypair(publickey, secretkey);

  cpp11::writable::raws ret_sk(SPX_SHA256F_CRYPTO_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(SPX_SHA256F_CRYPTO_PUBLICKEYBYTES);
  for(int i = 0; i < SPX_SHA256F_CRYPTO_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < SPX_SHA256F_CRYPTO_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }
  return cpp11::writable::list{ret_sk, ret_pk};
}
