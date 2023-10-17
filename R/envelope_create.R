
#' Envelope - Create
#'
#' @param message     Message to be encrypted and sent.
#' @param public_key  The public key produced by `keygen_kyber()` used to encapsulate the encryption
#'   key used to encrypt the message.
#'
#' @return  Invisibly, an envelope with encrypted message and encapsulated key.
#' @export
#'
#' @examples
#' key <- keygen_kyber(512)
#' env <- envelope_create("Very important message.", key$public)
envelope_create <- function(message, public_key) {

  if (!inherits(public_key, "pqcrypto_public_key")) {
    pq_stop(c(x = "'public_key' parameter does not have the expected class.",
              i = "'public_key' must have `pqcrypto_public_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.1.?", attr(public_key, "algorithm"))) {
    pq_stop(c(x = "Wrong public key algorithm.",
              i = "Make sure you are using a 'Kyber' public key."))
  }

  envelope <- as.cms_enveloped_data(message, public_key)

  invisible(envelope)
}
