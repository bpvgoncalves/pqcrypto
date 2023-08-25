#include <cpp11.hpp>
extern "C" {
  #include "kyber/api.h"
}


[[cpp11::register]]
cpp11::list cpp_keygen_kyber512() {

  uint8_t secretkey[pqcrystals_kyber512_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_kyber512_PUBLICKEYBYTES];
  int result = pqcrystals_kyber512_ref_keypair(publickey, secretkey);

  cpp11::writable::integers ret_sk(pqcrystals_kyber512_SECRETKEYBYTES);
  cpp11::writable::integers ret_pk(pqcrystals_kyber512_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_kyber512_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_kyber512_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}


[[cpp11::register]]
cpp11::list cpp_keygen_kyber768() {

  uint8_t secretkey[pqcrystals_kyber768_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_kyber768_PUBLICKEYBYTES];
  int result = pqcrystals_kyber768_ref_keypair(publickey, secretkey);

  cpp11::writable::integers ret_sk(pqcrystals_kyber768_SECRETKEYBYTES);
  cpp11::writable::integers ret_pk(pqcrystals_kyber768_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_kyber768_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_kyber768_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}


[[cpp11::register]]
cpp11::list cpp_keygen_kyber1024() {

  uint8_t secretkey[pqcrystals_kyber1024_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_kyber1024_PUBLICKEYBYTES];
  int result = pqcrystals_kyber1024_ref_keypair(publickey, secretkey);

  cpp11::writable::integers ret_sk(pqcrystals_kyber1024_SECRETKEYBYTES);
  cpp11::writable::integers ret_pk(pqcrystals_kyber1024_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_kyber1024_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_kyber1024_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}
