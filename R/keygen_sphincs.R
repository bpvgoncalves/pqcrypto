
#' Key-Pair Generation - Sphincs+
#'
#' @param hash_type  Type of hash to use. Accepts 'shake' (default) or 'sha2'.
#' @param category   Security category: 128 (claimed security category 1), 192 (default, claimed
#'    security category 2) and 256 (claimed security category 3).
#'    For more details regarding security categories please refer to the vignette.
#' @param type       Type of signature to produce: 'fast' (but larger) or 'small' (but slower).
#'
#' @return A `pqcrypto_keypair` object.
#'
#' @export
#'
#' @examples
#' key <- keygen_sphincs()
#' key$algorithm
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
      } else {
        key <- cpp_keygen_sphincsshake128s()
      }
    } else if (category == 192) {
      if (type == "fast") {
        key <- cpp_keygen_sphincsshake192f()
      } else {
        key <- cpp_keygen_sphincsshake192s()
      }
    } else {
      if (type == "fast") {
        key <- cpp_keygen_sphincsshake256f()
      } else {
        key <- cpp_keygen_sphincsshake256s()
      }
    }
  }

  keypair <- list(algorithm = "sphincs+",
                  params = list(hash = hash_type,
                                category = category,
                                type = type),
                  private = structure(key[[1]],
                                      algorithm = "sphincs+",
                                      params = list(hash = hash_type,
                                                    category = category,
                                                    type = type),
                                      class = "pqcrypto_private_key"),
                  public = structure(key[[2]],
                                     algorithm = "sphincs+",
                                     params = list(hash = hash_type,
                                                   category = category,
                                                   type = type),
                                     class = "pqcrypto_public_key"))
  class(keypair) <- c("pqcrypto_keypair")

  rm(key)
  return(keypair)
}
