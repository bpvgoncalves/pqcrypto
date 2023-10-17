
#' Envelope - Open
#'
#' @param envelope     An envelope produced by `envelope_create()`.
#' @param private_key  A private key able to decapsulate the encryption key contained in the
#'   envelope. It must be the private key paired with the public key used during envelope creation.
#'
#' @return   The message.
#' @export
#'
#' @examples
#' key <- keygen_kyber(512)
#' env <- envelope_create("Very important message.", key$public)
#'
#' msg <- envelope_open(env, key$private)
#' print(msg)
envelope_open <- function(envelope, private_key) {

  if (!inherits(envelope, "pqcrypto_cms_id_enveloped_data")) {
    pq_stop(c(x = "'envelope' parameter does not have the expected class.",
              i = "'envelope' must have `pqcrypto_cms_id_enveloped_data` class."))
  }

  if (!inherits(private_key, "pqcrypto_private_key")) {
    pq_stop(c(x = "'private_key' parameter does not have the expected class.",
              i = "'private_key' must have `pqcrypto_private_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.1.?", attr(private_key, "algorithm"))) {
    pq_stop(c(x = "Wrong private key algorithm.",
              i = "Make sure you are using a 'Kyber' private key."))
  }

  shared_key <- decap_kyber(envelope$recipient_infos$encrypted_key, private_key)
  iv <- envelope$encrypted_content_info$content_encryption_algorithm$param_iv
  message <- openssl::aes_cbc_decrypt(envelope$encrypted_content_info$encrypted_content,
                                      shared_key,
                                      iv)
  unserialize(message)
}
