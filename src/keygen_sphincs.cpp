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
