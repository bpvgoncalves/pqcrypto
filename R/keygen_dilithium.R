
#' Key-Pair Generation - Dilithium
#'
#' @param strength  Type of key strength to be generated.
#'    Different strengths are available. Use 2 for Dilithium2 (claimed strength
#'    category 2), 3 for Dilithium3 (default, claimed strength category 3) or 5
#'    for Dilithium5 (claimed strength category 5).
#'    For more information about strength categories see the vignette.
#'
#' @return A `keypair` object.
#'
#' @export
#'
#' @examples
#' key <- keygen_dilithium()
#' key$algorithm
#'
keygen_dilithium <- function(strength = 3) {

  if (strength == 2) {
    key <- cpp_keygen_dilithium2()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.2.1"
  } else if (strength == 3) {
    key <- cpp_keygen_dilithium3()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.2.2"
  } else if (strength == 5) {
    key <- cpp_keygen_dilithium5()
    algo <- "1.3.6.1.4.1.54392.5.1859.1.2.3"
  } else {
    pq_stop(c(x = "Unknown 'strength' value: {.val {strength}}.",
              i = "Acceptable values are 2, 3 or 5."))
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
                                     key_id = id,
                                     class = "pqcrypto_public_key"))
  class(keypair) <- "pqcrypto_keypair"

  rm(key)
  return(keypair)
}
