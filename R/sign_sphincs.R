
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

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.3.?", attr(private_key, "algorithm"))) {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  if (!(length(private_key) %in% c(64, 96, 128))) {
    pq_stop(c(x = "Wrong private key size.",
              i = "Make sure you are using a 'Sphincs+' private key."))
  }

  ts <- get_timestamp()
  raw_msg <- msg_to_raw(c(message,                         # Actual Message
                          attr(private_key, "algorithm"),  # Signature Algorithm
                          "2.16.840.1.101.3.4.2.10",       # Digest Algorithm
                          ts))                             # Timestamp
  message_digest <- openssl::sha3(raw_msg, 512)

  last_digit <- as.integer(substring(attr(private_key, "algorithm"),
                                     regexpr("\\.[^\\.]*$", attr(private_key, "algorithm"))+1))
  fast_signature <- ifelse(last_digit %in% c(3, 4, 7, 8, 11, 12), TRUE, FALSE)

  content <- as.cms_data(message)
  signed_attrs <- list(list("1.2.840.113549.1.9.3", "1.2.840.113549.1.7.1"),
                       list("1.2.840.113549.1.9.4", openssl::sha3(c(content), 512)),
                       list("1.2.840.113549.1.9.5", get_timestamp()))
  class(signed_attrs) <- "pqcrypto_cms_signed_attrs"

  der_attrs <- as.der(signed_attrs)
  attrs_digest <- openssl::sha3(der_attrs, 512)

  if (last_digit %% 2 == 0) {
    dig_signature <- cpp_sign_sphincs_shake(attrs_digest, private_key, fast_signature)
  } else if (last_digit %% 2 == 1) {
    dig_signature <- cpp_sign_sphincs_sha2(attrs_digest, private_key, fast_signature)
  }

  s_info <- as.cms_signature_info(private_key, signed_attrs, dig_signature)
  signed_data <- as.cms_signed_data(content, s_info)

  invisible(signed_data)
}
