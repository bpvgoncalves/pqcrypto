
#ifndef PARAMS
#define PARAMS 1
#endif

/*
 *  1: shake128s
 *  2: shake128f
 *  3: shake192s
 *  4: shake192f
 *  5: shake256s
 *  6: shake256f
 */
#if PARAMS == 1
  #include "params/params-sphincs-shake-128s.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE128S_##s
#elif PARAMS == 2
  #include "params/params-sphincs-shake-128f.h"
  #define SPX_NAMESPACE(s) SPX_SHAKE128F_##s
#endif

#define CRYPTO_ALGNAME "SPHINCS+"
#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3*SPX_N)

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
