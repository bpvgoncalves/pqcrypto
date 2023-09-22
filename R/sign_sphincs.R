
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
#' signature <- sign_sphincs(key$private, important_message)
#' signature[1:16]   # first 16 bytes of the signature
#'
sign_sphincs <- function(private_key, message) {

  if (!inherits(private_key, "pqcrypto_private_key")) {
    pq_stop(c(x = "'private_key' parameter does not have the expected class.",
              i = "'private_key' must have `pqcrypto_private_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.3.?", private_key$algorithm)) {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  if (!(length(private_key$key) %in% c(64, 96, 128))) {
    pq_stop(c(x = "Wrong private key size.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  message <- msg_to_raw(message)

  last_digit <- as.integer(substring(private_key$algorithm,
                                     regexpr("\\.[^\\.]*$", private_key$algorithm)+1))
  fast_signature <- ifelse(last_digit %in% c(3, 4, 7, 8, 11, 12), TRUE, FALSE)

  if (last_digit %% 2 == 0) {
    dig_signature <- cpp_sign_sphincs_shake(message, private_key$key, fast_signature)
  } else if (last_digit %% 2 == 1) {
    dig_signature <- cpp_sign_sphincs_sha2(message, private_key$key, fast_signature)
  }

  attr(dig_signature, "algorithm") <- "sphincs+"
  class(dig_signature) <- "pqcrypto_signature"
  dig_signature
}
