
#' Key-Pair Generation - Kyber
#'
#' @param param_set  Type of key to be generated.
#'    Use 512 for Kyber-512, 768 (default) for Kyber-768 or 1024 for Kyber-1024.
#'
#' @return A `keypair` object.
#' @export
#'
#' @examples
#' key <- keygen_kyber()
#' key$algorithm
#'
keygen_kyber <- function(param_set = 768) {

  param_set <- as.integer(param_set)
  if (param_set == 512L) {
    key <- cpp_keygen_kyber512()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.1.1"
  } else if (param_set == 768L) {
    key <- cpp_keygen_kyber768()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.1.2"
  } else if (param_set == 1024L) {
    key <- cpp_keygen_kyber1024()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.1.3"
  } else {
    pq_stop(c(x = "Unknown 'param_set' value: {.val {param_set}}.",
              i = "Acceptable values are 512, 768 or 1024."))
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
