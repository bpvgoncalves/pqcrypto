
#' Digital Signature - Verify ML-DSA (FIPS 204)
#'
#' @description
#' Verifies that the signature of a given message is valid.
#'
#' @param message     The message that has been signed.
#'    As in `sign_ml_dsa()`, message may be interpreted in lax terms. It is
#'    possible to sign any type of R objects, not only text strings.
#' @param signature   The signature produced by `sign_ml_dsa()`.
#' @param public_key  The public key created by `keygen_ml_dsa()` that is
#'    paired with the private key used for signing.
#'
#' @return  Prints the signature validation outcome and silently returns TRUE
#'    if the signature verifies successfully or FALSE otherwise.
#'
#' @export
#'
#' @examples
#' key <- keygen_ml_dsa(2)
#' important_message <- "Hello world!!"
#' signature <- sign_ml_dsa(key$private, important_message)
#' verify_ml_dsa(important_message, signature, key$public)
#'
verify_ml_dsa <- function(message, signature, public_key) {

  if (!inherits(signature, "pqcrypto_cms_id_signed_data")) {
    pq_stop(c(x = "'signature' parameter does not have the expected class.",
              i = "'signature' must have `pqcrypto_cms_id_signed_data` class."))
  }

  if (!inherits(public_key, "pqcrypto_public_key")) {
    pq_stop(c(x = "'public_key' parameter does not have the expected class.",
              i = "'public_key' must have `public_key` class."))
  }

  if (!grepl("1.3.6.1.4.1.54392.5.1859.1.2.?", attr(public_key, "algorithm"))) {
    pq_stop(c(x = "Wrong public key algorithm.",
              i = "Make sure you are using a 'ML-DSA' public key."))
  }

  if (!identical(signature$signer_infos$sid, unclass(openssl::sha3(public_key, 224)))) {
    expected_key <- PKI::raw2hex(signature$signer_infos$sid, ":")
    pq_stop(c(x = "Key mismatch.",
              "Are you using the public key paired with signer's private key?",
              i = "Expected key_id: {.val {expected_key}}"))
  }

  content <- as.cms_data(message)
  if (!identical(content, signature$encap_content_info)) {
    pq_msg(c(x = "Signature integrity check failed.",
             i = "Encapsulated content not matching message."))
    return(FALSE)
  }

  content_digest <- openssl::sha3(c(signature$encap_content_info), 512)
  signed_content_digest <- signature$signer_infos$signed_attrs[[2]][[2]]
  if (!identical(c(content_digest), c(signed_content_digest))) {
    pq_msg(c(x = "Signature integrity check failed.",
             i = "Encapsulated content digest not matching signed content digest."))
    return(FALSE)
  }

  attrs_digest <- openssl::sha3(as.der(signature$signer_infos$signed_attrs), 512)
  result <- cpp_verify_dilithium(signature$signer_infos$signature,
                                 attrs_digest,
                                 public_key)
  result <- !as.logical(result)

  if (result) {
    ts <- as.character(signature$signer_infos$signed_attrs[[3]][[2]])
    pq_msg(c(v = "The signature has been verified successfully.",
             i = paste("Signature produced on:", ts)))
  } else {
    pq_msg(c(x = "The signature could not be verified successfully.",
             i = "This may indicate that the message and/or the signature were tampered with."))
  }

  invisible(result)
}


#' Dilithium Digital Signature - Verify
#'
#' @description
#' `r lifecycle::badge("deprecated")`
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
#' @keywords internal
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' signature <- sign_dilithium(key$private, important_message)
#' verify_dilithium(important_message, signature, key$public)
#' # ->
#' verify_ml_dsa(important_message, signature, key$public)
#'
verify_dilithium <- function(message, signature, public_key) {
  lifecycle::deprecate_soft("0.3.0", "verify_dilithium()", "verify_ml_dsa()")

  verify_ml_dsa(message, signature, public_key)
}
