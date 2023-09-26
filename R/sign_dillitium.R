
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

  content <- as.cms_data(message)
  signed_attrs <- list(list("1.2.840.113549.1.9.3", "1.2.840.113549.1.7.1"),
                       list("1.2.840.113549.1.9.4", openssl::sha3(c(content), 512)),
                       list("1.2.840.113549.1.9.5", get_timestamp()))
  class(signed_attrs) <- "pqcrypto_cms_signed_attrs"

  der_attrs <- as.der(signed_attrs)
  attrs_digest <- openssl::sha3(der_attrs, 512)

  dig_signature <- cpp_sign_dilithium(attrs_digest, private_key)

  s_info <- as.cms_signature_info(private_key, signed_attrs, dig_signature)
  signed_data <- as.cms_signed_data(content, s_info)

  invisible(signed_data)
}
