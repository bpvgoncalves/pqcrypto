
as.key <- function(object, ...) {
  UseMethod("as.key")
}


as.key.pqcrypto_der_encrypted_private_key <- function(d) {

  struct <- PKI::ASN1.decode(d)

  encryption_algoritm <- as.character(PKI::as.oid(struct[[1]][[1]]))
  aes_iv <- struct[[1]][[2]]
  ciphertext <- struct[[2]]
  attr(ciphertext, "iv") <- aes_iv

  invisible(ciphertext)
}

as.key.pqcrypto_der_private_key <- function(d) {

  struct <- PKI::ASN1.decode(d)

  version <- as.integer(PKI::ASN1.decode(struct[[1]])[[1]])
  key_algoritm <- as.character(PKI::as.oid(struct[[2]][[1]]))
  key <- c(struct[[3]])
  id <- c(PKI::ASN1.decode(struct[[4]])[[1]][[3]])

  pk <- structure(key,
                  version = version,
                  algorithm = key_algoritm,
                  key_id = id,
                  class = "pqcrypto_private_key")

  invisible(pk)
}

as.key.pqcrypto_der_public_key <- function(d) {

  struct <- PKI::ASN1.decode(d)

  key_algoritm <- as.character(PKI::as.oid(struct[[1]][[1]]))
  key <- c(struct[[2]])

  pk <- structure(key,
                  algorithm = key_algoritm,
                  class = "pqcrypto_public_key")

  invisible(pk)
}
