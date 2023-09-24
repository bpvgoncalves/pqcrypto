
#' Sphincs+ Digital Signature - Verify
#'
#' Verifies that the signature of a given message is valid.
#'
#' @param message     The message that has been signed.
#'    As in `sign_sphincs()`, message may be interpreted in lax terms. It is
#'    possible to sign any type of R objects, not only text strings.
#' @param signature   The signature produced by `sign_sphincs()`.
#' @param public_key  The public key created by `keygen_sphincs()` that is
#'    paired with the private key used for signing.
#'
#' @return  Prints the signature validation outcome and silently returns TRUE
#'    if the signature verifies successfully or FALSE otherwise.
#'
#' @export
#'
#' @examples
#' key <- keygen_sphincs("sha2", 256, "fast")
#' important_message <- "Hello world!!"
#' signature <- sign_sphincs(key$private, important_message)
#' verify_sphincs(important_message, signature, key$public)   # Should be OK
#'
#' # Try to verify an tampered message
#' verify_sphincs("not_the_message", signature, key$public)   # Should Fail
verify_sphincs <- function(message, signature, public_key) {

  if (!inherits(signature, "pqcrypto_signature")) {
    pq_stop(c(x = "'signature' parameter does not have the expected class.",
              i = "'signature' must have `pqcrypto_signature` class."))
  }

  if (!inherits(public_key, "pqcrypto_public_key")) {
    pq_stop(c(x = "'public_key' parameter does not have the expected class.",
              i = "'public_key' must have `public_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.3.?", attr(public_key, "algorithm"))) {
    pq_stop(c(x = "Wrong public key algorithm.",
              i = "Make sure you are using a 'Sphincs+' public key."))
  }

  if (!identical(attr(signature, "key_id"), attr(public_key, "key_id"))) {
    expected_key <- PKI::raw2hex(attr(signature, "key_id"), ":")
    pq_stop(c(x = "Key mismatch.",
              "Are you using the public key paired with signer's private key?",
              i = "Expected key_id: {.val {expected_key}}"))
  }

  raw_msg <- msg_to_raw(c(message,                             # Message
                          attr(signature, "sign_algorithm"),   # Signature Algorithm
                          attr(signature, "digest_algorithm"), # Digest Algorithm
                          attr(signature, "timestamp")))       # Timestamp
  message_digest <- openssl::sha3(raw_msg, 512)

  last_digit <- as.integer(substring(attr(public_key, "algorithm"),
                                     regexpr("\\.[^\\.]*$", attr(public_key, "algorithm"))+1))
  if (last_digit %% 2 == 0) {
    result <- cpp_verify_sphincs_shake(signature, message_digest, public_key)
  } else if (last_digit %% 2 == 1) {
    result <- cpp_verify_sphincs_sha2(signature, message_digest, public_key)
  }
  result <- !as.logical(result)

  if (result) {
    pq_msg(c(v = "The signature has been verified successfully.",
             i = "Signature produced on: {.val {attr(signature, \"timestamp\")}}"))
  } else {
    pq_msg(c(x = "The signature could not be verified successfully.",
             i = "This may indicate that the message was tampered with."))
  }

  invisible(result)
}
