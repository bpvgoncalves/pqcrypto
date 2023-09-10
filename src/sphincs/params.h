
#ifndef PARAMS
#define PARAMS 1
#endif

/*
 *  1: shake128s     7: sha128s
 *  2: shake128f     8: sha128f
 *  3: shake192s     9: sha192s
 *  4: shake192f    10: sha192f
 *  5: shake256s    11: sha256s
 *  6: shake256f    12: sha256f
 */
#if PARAMS == 1
  #include "params/params-sphincs-shake-128s.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE128S_##s
#elif PARAMS == 2
  #include "params/params-sphincs-shake-128f.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE128F_##s
#elif PARAMS == 3
  #include "params/params-sphincs-shake-192s.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE192S_##s
#elif PARAMS == 4
  #include "params/params-sphincs-shake-192f.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE192F_##s
#elif PARAMS == 5
  #include "params/params-sphincs-shake-256s.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE256S_##s
#elif PARAMS == 6
  #include "params/params-sphincs-sha2-256f.h"
  #define SPX_NAMESPACE(s) SPX_SHA256F_##s
#elif PARAMS == 7
  #include "params/params-sphincs-sha2-128s.h"
  #define SPX_NAMESPACE(s) SPX_SHA128S_##s
#elif PARAMS == 8
  #include "params/params-sphincs-sha2-128f.h"
  #define SPX_NAMESPACE(s) SPX_SHA128F_##s
#elif PARAMS == 9
  #include "params/params-sphincs-sha2-192s.h"
  #define SPX_NAMESPACE(s) SPX_SHA192S_##s
#elif PARAMS == 10
  #include "params/params-sphincs-sha2-192f.h"
  #define SPX_NAMESPACE(s) SPX_SHA192F_##s
#elif PARAMS == 11
  #include "params/params-sphincs-sha2-256s.h"
  #define SPX_NAMESPACE(s) SPX_SHA256S_##s
#elif PARAMS == 12
  #include "params/params-sphincs-sha2-256f.h"
  #define SPX_NAMESPACE(s) SPX_SHA256F_##s
#else
  #error "PARAMS must be between 1 and 12."
#endif

#define CRYPTO_ALGNAME         "SPHINCS+"
#define CRYPTO_SECRETKEYBYTES  SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES  SPX_PK_BYTES
#define CRYPTO_BYTES           SPX_BYTES
#define CRYPTO_SEEDBYTES       (3*SPX_N)

#define crypto_sign_secretkeybytes SPX_NAMESPACE(crypto_sign_secretkeybytes)
unsigned long long crypto_sign_secretkeybytes(void);

#define crypto_sign_publickeybytes SPX_NAMESPACE(crypto_sign_publickeybytes)
unsigned long long crypto_sign_publickeybytes(void);

#define crypto_sign_bytes SPX_NAMESPACE(crypto_sign_bytes)
unsigned long long crypto_sign_bytes(void);

#define crypto_sign_seedbytes SPX_NAMESPACE(crypto_sign_seedbytes)
unsigned long long crypto_sign_seedbytes(void);

#define crypto_sign_seed_keypair SPX_NAMESPACE(crypto_sign_seed_keypair)
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed);

#define crypto_sign_keypair SPX_NAMESPACE(crypto_sign_keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign_signature SPX_NAMESPACE(crypto_sign_signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);

#define crypto_sign_verify SPX_NAMESPACE(crypto_sign_verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

#define crypto_sign SPX_NAMESPACE(crypto_sign)
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);

#define crypto_sign_open SPX_NAMESPACE(crypto_sign_open)
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
