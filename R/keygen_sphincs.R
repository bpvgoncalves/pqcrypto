
#' Key-Pair Generation - Sphincs+
#'
#' @param hash_type  Type of hash to use. Accepts 'shake' (default) or 'sha2'.
#' @param category   Security category: 128 (claimed security category 1), 192 (default, claimed
#'    security category 2) and 256 (claimed security category 3).
#'    For more details regarding security categories please refer to the vignette.
#' @param type       Type of signature to produce: 'fast' (but having a larger size) or 'small'
#'    (but being slower to compute).
#'
#' @return A `pqcrypto_keypair` object.
#'
#' @export
#'
#' @examples
#' # Generate key with default parameters
#' key1 <- keygen_sphincs()
#' key1$algorithm
#' key1$param$hash
#'
#' # Generate key with custom parameters
#' key2 <- keygen_sphincs("sha2", 128, "small")
#' key2$algorithm
#' key2$param$hash
#'
keygen_sphincs <- function(hash_type = "shake", category = 192, type = "fast") {

  if (!(hash_type %in% c("shake", "sha2"))) {
    pq_stop(c(x = "Wrong 'hash_type' choosen.",
              i = "Make sure you are using 'shake' or 'sha2'."))
  }

  if (!(category %in% c(128, 192, 256))) {
    pq_stop(c(x = "Wrong 'category'.",
              i = "Make sure you are using 128, 192 or 256."))
  }

  if (!(type %in% c("fast", "small"))) {
    pq_stop(c(x = "Wrong 'type'.",
              i = "Make sure you are using 'fast' or 'small'."))
  }

  if (hash_type == "shake") {
    if (category == 128) {
      if (type == "fast") {
        key <- cpp_keygen_sphincsshake128f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.4"
      } else {
        key <- cpp_keygen_sphincsshake128s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.2"
      }
    } else if (category == 192) {
      if (type == "fast") {
        key <- cpp_keygen_sphincsshake192f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.8"
      } else {
        key <- cpp_keygen_sphincsshake192s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.6"
      }
    } else {
      if (type == "fast") {
        key <- cpp_keygen_sphincsshake256f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.12"
      } else {
        key <- cpp_keygen_sphincsshake256s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.10"
      }
    }
  } else {
    if (category == 128) {
      if (type == "fast") {
        key <- cpp_keygen_sphincssha128f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.3"
      } else {
        key <- cpp_keygen_sphincssha128s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.1"
      }
    } else if (category == 192) {
      if (type == "fast") {
        key <- cpp_keygen_sphincssha192f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.7"
      } else {
        key <- cpp_keygen_sphincssha192s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.5"
      }
    } else {
      if (type == "fast") {
        key <- cpp_keygen_sphincssha256f()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.11"
      } else {
        key <- cpp_keygen_sphincssha256s()
        algo <- "1.3.6.1.4.1.54392.5.1859.1.3.9"
      }
    }
  }


  id <- unclass(openssl::sha3(key[[2]], 224))
  keypair <- list(creation = get_timestamp(),
                  private = structure(key[[1]],
                                      version = 0L,
                                      algorithm = algo,
                                      key_id = id,
                                      class = "pqcrypto_private_key"),
                  public = structure(key[[2]],
                                     algorithm = algo,
                                     class = "pqcrypto_public_key"))
  class(keypair) <- "pqcrypto_keypair"

  rm(key)
  return(keypair)
}
