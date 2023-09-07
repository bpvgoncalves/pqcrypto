
#' Dilithium Digital Signature - Verify
#'
#' Verifies that the signature of a given message is valid.
#'
#' @param message     The message that has been signed.
#'    As in `sign_dilithium()`, message may be interpreted in lax terms. It is
#'    possible to sign any type of R objects, not only text strings.
#' @param signature   The signature produced by `sign_dilithium()`.
#' @param public_key  The public key created by `keygen_dilithium()` that is
#'    paired with the private key used for signing.
#'
#' @return  Prints the signature validation outcome and silently returns TRUE
#'    if the signature verifies successfully or FALSE otherwise.
#'
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' signature <- sign_dilithium(key$private, important_message)
#' verify_dilithium(important_message, signature, key$public)
#'
verify_dilithium <- function(message, signature, public_key) {

  message <- msg_to_raw(message)

  if (!inherits(signature, "pqcrypto_signature")) {
    pq_stop(c(x = "'signature' parameter does not have the expected class.",
              i = "'signature' must have `pqcrypto_signature` class."))
  }

  if (!inherits(public_key, "pqcrypto_public_key")) {
    pq_stop(c(x = "'public_key' parameter does not have the expected class.",
              i = "'public_key' must have `public_key` class."))
  }

  if (attr(public_key, "algorithm") != "dilithium") {
    pq_stop(c(x = "Wrong public key algorithm.",
              i = "Make sure you are using a 'Dilithium' public key."))
  }

  result <- cpp_verify_dilithium(signature, message, public_key)
  result <- !as.logical(result)

  if (result) {
    pq_msg(c(v = "The signature has been verified successfully."))
  } else {
    pq_msg(c(x = "The signature could not be verified successfully.",
             i = "This may indicate that the message was tampered with."))
  }

  invisible(result)
}
