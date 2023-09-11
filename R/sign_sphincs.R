
#' Sphincs+ Digital Signature - Sign
#'
#' Produces a digital signature of a given message.
#'
#' @param private_key A private key produced by `keygen_sphincs()` to be used
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
#' key <- keygen_sphincs()
#' important_message <- "Hello world!!"
#' sig <- sign_sphincs(key$private, important_message)
#' sig[1:10]   # first 10 bytes of the signature
#'
sign_sphincs <- function(private_key, message) {

  if (!inherits(private_key, "pqcrypto_private_key")) {
    pq_stop(c(x = "'private_key' parameter does not have the expected class.",
              i = "'private_key' must have `pqcrypto_private_key` class."))
  }

  if (attr(private_key, "algorithm") != "sphincs+") {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  if (!(length(private_key) %in% c(64, 96, 128))) {
    pq_stop(c(x = "Wrong private key size.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  message <- msg_to_raw(message)
  fast_signature <- ifelse(attr(private_key, "params")$type == "fast", TRUE, FALSE)

  dig_signature <- cpp_sign_sphincs_shake(message, private_key, fast_signature)
  attr(dig_signature, "algorithm") <- "sphincs+"
  class(dig_signature) <- "pqcrypto_signature"
  dig_signature
}
