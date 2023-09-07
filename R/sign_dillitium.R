
#' Dilithium Digital Signature - Sign
#'
#' Produces a digital signature of a given message.
#'
#' @param private_key A private key produced by `keygen_dilithium()` to be used
#'    for message signing.
#' @param message     The message to be signed. Message may be interpreted in
#'    very lax terms. Pretty much any R object can be signed, not only
#'    character strings.
#'
#' @return A `pqcrypto_signature`' object.
#'
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' sig <- sign_dilithium(key$private, important_message)
#' sig[1:10]
#'
sign_dilithium <- function(private_key, message) {

  if (!inherits(private_key, "pqcrypto_private_key")) {
    pq_stop(c(x = "'private_key' parameter does not have the expected class.",
              i = "'private_key' must have `private_key` class."))
  }

  if (attr(private_key, "algorithm") != "dilithium") {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Dilithium' private key."))
  }

  message <- msg_to_integer(message)

  dig_signature <- cpp_sign_dilithium(message, private_key)
  attr(dig_signature, "algorithm") <- "dilithium"
  class(dig_signature) <- "pqcrypto_signature"
  dig_signature
}