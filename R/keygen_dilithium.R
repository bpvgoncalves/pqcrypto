
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
  } else if (strength == 3) {
    key <- cpp_keygen_dilithium3()
  } else if (strength == 5) {
    key <- cpp_keygen_dilithium5()
  } else {
    pq_stop(c(x = "Unknown 'strength' value: {.val {strength}}.",
              i = "Acceptable values are 2, 3 or 5."))
  }

  keypair <- list(algorithm = "dilithium",
                  strength = strength,
                  private = structure(key[[1]],
                                      algorithm = "dilithium",
                                      strength = strength,
                                      class = "pqcrypto_private_key"),
                  public = structure(key[[2]],
                                     algorithm = "dilithium",
                                     strength = strength,
                                     class = "pqcrypto_public_key"))
  class(keypair) <- c("pqcrypto_keypair")

  rm(key)
  return(keypair)
}
