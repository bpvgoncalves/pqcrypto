
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
              i = "'private_key' must have `pqcrypto_private_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.2.?", attr(private_key, "algorithm"))) {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Dilithium' private key."))
  }

  if (!(length(private_key) %in% c(2560, 4032, 4896))) {
    pq_stop(c(x = "Wrong private key size.",
              i = "Make sure you are using a 'Dilithium' private key."))
  }

  ts <- get_timestamp()
  raw_msg <- msg_to_raw(c(message,                         # Actual Message
                          attr(private_key, "algorithm"),  # Signature Algorithm
                          "2.16.840.1.101.3.4.2.10",       # Digest Algorithm
                          ts))                             # Timestamp
  message_digest <- openssl::sha3(raw_msg, 512)
  dig_signature <- cpp_sign_dilithium(message_digest, private_key)
  attr(dig_signature, "sign_algorithm") <- attr(private_key, "algorithm")
  attr(dig_signature, "digest_algorithm") <- "2.16.840.1.101.3.4.2.10"
  attr(dig_signature, "key_id") <- attr(private_key, "key_id")
  attr(dig_signature, "timestamp") <- ts
  class(dig_signature) <- "pqcrypto_signature"

  invisible(dig_signature)
}
