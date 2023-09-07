#include <cpp11.hpp>
extern "C" {
  #include "dilithium/api.h"
}

[[cpp11::register]]
cpp11::list cpp_keygen_dilithium2() {

  uint8_t secretkey[pqcrystals_dilithium2_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_dilithium2_PUBLICKEYBYTES];
  int result = pqcrystals_dilithium2_ref_keypair(publickey, secretkey);
  if (result != 0) {
    cpp11::stop("Something went wrong with the key generation.");
  }

  cpp11::writable::raws ret_sk(pqcrystals_dilithium2_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(pqcrystals_dilithium2_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_dilithium2_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_dilithium2_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_dilithium3() {

  uint8_t secretkey[pqcrystals_dilithium3_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_dilithium3_PUBLICKEYBYTES];
  int result = pqcrystals_dilithium3_ref_keypair(publickey, secretkey);
  if (result != 0) {
    cpp11::stop("Something went wrong with the key generation.");
  }

  cpp11::writable::raws ret_sk(pqcrystals_dilithium3_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(pqcrystals_dilithium3_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_dilithium3_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_dilithium3_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}

[[cpp11::register]]
cpp11::list cpp_keygen_dilithium5() {

  uint8_t secretkey[pqcrystals_dilithium5_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_dilithium5_PUBLICKEYBYTES];
  int result = pqcrystals_dilithium5_ref_keypair(publickey, secretkey);
  if (result != 0) {
    cpp11::stop("Something went wrong with the key generation.");
  }

  cpp11::writable::raws ret_sk(pqcrystals_dilithium5_SECRETKEYBYTES);
  cpp11::writable::raws ret_pk(pqcrystals_dilithium5_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_dilithium5_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_dilithium5_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}
