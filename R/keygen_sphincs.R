

keygen_sphincs <- function() {

  key <- cpp_keygen_sphincsshake128s()

  keypair <- list(algorithm = "sphincs+",
                  strength = 128,
                  private = structure(key[[1]],
                                      algorithm = "sphincs+",
                                      strength = 128,
                                      class = "pqcrypto_private_key"),
                  public = structure(key[[2]],
                                     algorithm = "sphincs+",
                                     strength = 128,
                                     class = "pqcrypto_public_key"))
  class(keypair) <- c("pqcrypto_keypair")

  rm(key)
  return(keypair)
}
