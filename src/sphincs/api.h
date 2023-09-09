#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#define SPX_SHAKE128S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE128_S"
#define SPX_SHAKE128S_CRYPTO_SECRETKEYBYTES  64
#define SPX_SHAKE128S_CRYPTO_PUBLICKEYBYTES  32
#define SPX_SHAKE128S_CRYPTO_BYTES           7856
#define SPX_SHAKE128S_CRYPTO_SEEDBYTES       48

unsigned long long SPX_SHAKE128S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE128S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE128S__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE128S__crypto_sign_seedbytes(void);

int SPX_SHAKE128S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE128S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE128S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE128S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE128S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE128S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);



#endif
