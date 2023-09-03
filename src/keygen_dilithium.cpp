#include <cpp11.hpp>
extern "C" {
  #include "dilithium/api.h"
}

[[cpp11::register]]
cpp11::list cpp_keygen_dilithium2() {

  uint8_t secretkey[pqcrystals_dilithium2_SECRETKEYBYTES];
  uint8_t publickey[pqcrystals_dilithium2_PUBLICKEYBYTES];
  int result = pqcrystals_dilithium2_ref_keypair(publickey, secretkey);

  cpp11::writable::integers ret_sk(pqcrystals_dilithium2_SECRETKEYBYTES);
  cpp11::writable::integers ret_pk(pqcrystals_dilithium2_PUBLICKEYBYTES);
  for(int i = 0; i < pqcrystals_dilithium2_SECRETKEYBYTES; ++i) {
    ret_sk[i] = secretkey[i];
  }
  for(int i = 0; i < pqcrystals_dilithium2_PUBLICKEYBYTES; ++i) {
    ret_pk[i] = publickey[i];
  }

  return cpp11::writable::list{ret_sk, ret_pk};
}
