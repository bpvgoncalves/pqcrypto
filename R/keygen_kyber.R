
#' keygen
#'
#' @return
#' @export
#'
#' @examples
keygen_kyber <- function(param_set = 768) {

  param_set <- as.integer(param_set)

  key <- cpp_keygen_kyber768()
  keypair <- list(key_type = paste0("Kyber-", param_set),
                  secret = structure(key[[1]], class="secret_key"),
                  public = structure(key[[2]], class="public_key"))
  attr(keypair, "key_param") <- param_set
  class(keypair) <- c("keypair", "kyber")

  rm(key)
  return(keypair)
}
