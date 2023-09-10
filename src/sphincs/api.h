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


#define SPX_SHAKE128F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE128_F"
#define SPX_SHAKE128F_CRYPTO_SECRETKEYBYTES  64
#define SPX_SHAKE128F_CRYPTO_PUBLICKEYBYTES  32
#define SPX_SHAKE128F_CRYPTO_BYTES           17088
#define SPX_SHAKE128F_CRYPTO_SEEDBYTES       48

unsigned long long SPX_SHAKE128F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE128F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE128F__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE128F__crypto_sign_seedbytes(void);

int SPX_SHAKE128F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE128F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE128F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE128F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE128F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE128F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHAKE192S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE192_S"
#define SPX_SHAKE192S_CRYPTO_SECRETKEYBYTES  96
#define SPX_SHAKE192S_CRYPTO_PUBLICKEYBYTES  48
#define SPX_SHAKE192S_CRYPTO_BYTES           16224
#define SPX_SHAKE192S_CRYPTO_SEEDBYTES       72

unsigned long long SPX_SHAKE192S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE192S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE192S__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE192S__crypto_sign_seedbytes(void);

int SPX_SHAKE192S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE192S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE192S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE192S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE192S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE192S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHAKE192F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE192_F"
#define SPX_SHAKE192F_CRYPTO_SECRETKEYBYTES  96
#define SPX_SHAKE192F_CRYPTO_PUBLICKEYBYTES  48
#define SPX_SHAKE192F_CRYPTO_BYTES           35664
#define SPX_SHAKE192F_CRYPTO_SEEDBYTES       72

unsigned long long SPX_SHAKE192F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE192F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE192F__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE192F__crypto_sign_seedbytes(void);

int SPX_SHAKE192F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE192F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE192F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE192F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE192F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE192F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHAKE256S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE256_S"
#define SPX_SHAKE256S_CRYPTO_SECRETKEYBYTES  128
#define SPX_SHAKE256S_CRYPTO_PUBLICKEYBYTES  64
#define SPX_SHAKE256S_CRYPTO_BYTES           29792
#define SPX_SHAKE256S_CRYPTO_SEEDBYTES       96

unsigned long long SPX_SHAKE256S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE256S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE256S__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE256S__crypto_sign_seedbytes(void);

int SPX_SHAKE256S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE256S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE256S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE256S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE256S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE256S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHAKE256F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHAKE256_F"
#define SPX_SHAKE256F_CRYPTO_SECRETKEYBYTES  128
#define SPX_SHAKE256F_CRYPTO_PUBLICKEYBYTES  64
#define SPX_SHAKE256F_CRYPTO_BYTES           49856
#define SPX_SHAKE256F_CRYPTO_SEEDBYTES       96

unsigned long long SPX_SHAKE256F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHAKE256F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHAKE256F__crypto_sign_bytes(void);
unsigned long long SPX_SHAKE256F__crypto_sign_seedbytes(void);

int SPX_SHAKE256F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHAKE256F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHAKE256F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHAKE256F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHAKE256F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHAKE256F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA128S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA128_S"
#define SPX_SHA128S_CRYPTO_SECRETKEYBYTES  64
#define SPX_SHA128S_CRYPTO_PUBLICKEYBYTES  32
#define SPX_SHA128S_CRYPTO_BYTES           7856
#define SPX_SHA128S_CRYPTO_SEEDBYTES       48

unsigned long long SPX_SHA128S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA128S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA128S__crypto_sign_bytes(void);
unsigned long long SPX_SHA128S__crypto_sign_seedbytes(void);

int SPX_SHA128S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA128S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA128S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA128S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA128S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA128S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA128F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA128_F"
#define SPX_SHA128F_CRYPTO_SECRETKEYBYTES  64
#define SPX_SHA128F_CRYPTO_PUBLICKEYBYTES  32
#define SPX_SHA128F_CRYPTO_BYTES           17088
#define SPX_SHA128F_CRYPTO_SEEDBYTES       48

unsigned long long SPX_SHA128F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA128F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA128F__crypto_sign_bytes(void);
unsigned long long SPX_SHA128F__crypto_sign_seedbytes(void);

int SPX_SHA128F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA128F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA128F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA128F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA128F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA128F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA192S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA192_S"
#define SPX_SHA192S_CRYPTO_SECRETKEYBYTES  96
#define SPX_SHA192S_CRYPTO_PUBLICKEYBYTES  48
#define SPX_SHA192S_CRYPTO_BYTES           16224
#define SPX_SHA192S_CRYPTO_SEEDBYTES       72

unsigned long long SPX_SHA192S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA192S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA192S__crypto_sign_bytes(void);
unsigned long long SPX_SHA192S__crypto_sign_seedbytes(void);

int SPX_SHA192S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA192S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA192S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA192S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA192S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA192S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA192F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA192_F"
#define SPX_SHA192F_CRYPTO_SECRETKEYBYTES  96
#define SPX_SHA192F_CRYPTO_PUBLICKEYBYTES  48
#define SPX_SHA192F_CRYPTO_BYTES           35664
#define SPX_SHA192F_CRYPTO_SEEDBYTES       72

unsigned long long SPX_SHA192F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA192F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA192F__crypto_sign_bytes(void);
unsigned long long SPX_SHA192F__crypto_sign_seedbytes(void);

int SPX_SHA192F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA192F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA192F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA192F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA192F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA192F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA256S_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA256_S"
#define SPX_SHA256S_CRYPTO_SECRETKEYBYTES  128
#define SPX_SHA256S_CRYPTO_PUBLICKEYBYTES  64
#define SPX_SHA256S_CRYPTO_BYTES           29792
#define SPX_SHA256S_CRYPTO_SEEDBYTES       96

unsigned long long SPX_SHA256S__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA256S__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA256S__crypto_sign_bytes(void);
unsigned long long SPX_SHA256S__crypto_sign_seedbytes(void);

int SPX_SHA256S_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA256S_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA256S_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA256S_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA256S_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA256S_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);


#define SPX_SHA256F_CRYPTO_ALGNAME         "SPHINCSPLUS_SHA256_F"
#define SPX_SHA256F_CRYPTO_SECRETKEYBYTES  128
#define SPX_SHA256F_CRYPTO_PUBLICKEYBYTES  64
#define SPX_SHA256F_CRYPTO_BYTES           49856
#define SPX_SHA256F_CRYPTO_SEEDBYTES       96

unsigned long long SPX_SHA256F__crypto_sign_secretkeybytes(void);
unsigned long long SPX_SHA256F__crypto_sign_publickeybytes(void);
unsigned long long SPX_SHA256F__crypto_sign_bytes(void);
unsigned long long SPX_SHA256F__crypto_sign_seedbytes(void);

int SPX_SHA256F_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                                           const unsigned char *seed);
int SPX_SHA256F_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int SPX_SHA256F_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                                        size_t mlen, const uint8_t *sk);
int SPX_SHA256F_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                                     size_t mlen, const uint8_t *pk);
int SPX_SHA256F_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *sk);
int SPX_SHA256F_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                                   const unsigned char *sm, unsigned long long smlen,
                                   const unsigned char *pk);

#endif
