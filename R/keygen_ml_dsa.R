
#' Key-Pair Generation - ML-DSA (FIPS 204)
#'
#' @description
#' On 13/Aug/2024 NIST published the final version of the Module-Latice-Based
#' Digital Signature Standard (ML-DSA), based on Crystals-Dilithium submission.
#' This function generates a keypair to be used by the proposed Digital
#' Signature Algorithm.
#'
#' @param strength  Type of key strength to be generated.
#'    Different strengths are available. Use 2 for ML-DSA-44 (claimed strength
#'    category 2), 3 for ML-DSA-65 (default, claimed strength category 3) or 5
#'    for ML-DSA-87 (claimed strength category 5).
#'    For more information about strength categories see the vignette.
#'
#' @seealso https://csrc.nist.gov/pubs/fips/204/final
#'
#' @return A `keypair` object.
#'
#' @export
#'
#' @examples
#' key <- keygen_ml_dsa()
#' print(key)
#'
keygen_ml_dsa <- function(strength = 3) {

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
                                     class = "pqcrypto_public_key"))
  class(keypair) <- "pqcrypto_keypair"

  rm(key)
  return(keypair)
}


#' Key-Pair Generation - Dilithium
#'
#' `r lifecycle::badge("deprecated")`
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
#' @keywords internal
#'
#' @examples
#' key <- keygen_dilithium()
#' # ->
#' key <- keygen_ml_dsa()
#' print(key)
#'
keygen_dilithium <- function(strength = 3) {
  lifecycle::deprecate_soft("0.3.0", "keygen_dilithium()", "keygen_ml_dsa()")

  keygen_ml_dsa(strength)

}
