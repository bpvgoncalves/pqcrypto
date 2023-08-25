
#' Kyber Key Generation
#'
#' @param param_set  Type of key to be generated. Use 512 for Kyber-512, 768 (default) for Kyber-768
#' or 1024 for Kyber-1024.
#'
#' @return A `keypair` object
#' @export
#'
#' @examples
#' key <- keygen_kyber()
#' key$key_type
#'
keygen_kyber <- function(param_set = 768) {

  param_set <- as.integer(param_set)
  if (param_set == 512L) {
    key <- cpp_keygen_kyber512()
  } else if (param_set == 768L) {
    key <- cpp_keygen_kyber768()
  } else if (param_set == 1024L) {
    key <- cpp_keygen_kyber1024()
  } else {
    stop("Unknown 'parameter set'. Acceptable values: 512, 768 or 1024.")
  }

  keypair <- list(key_type = paste0("Kyber-", param_set),
                  secret = structure(key[[1]], class="secret_key"),
                  public = structure(key[[2]], class="public_key"))
  attr(keypair, "key_param") <- param_set
  class(keypair) <- c("keypair", "kyber")

  rm(key)
  return(keypair)
}
