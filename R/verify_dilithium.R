
#' Dilithium Digital Signature - Verify
#'
#' @param msg        The message
#' @param signature  The signature
#' @param public_key    The public key
#'
#' @return  TRUE if the signature verifies or FALSE otherwise.
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' sig <- sign_dilithium(key$private, important_message)
#' verify_dilithium(important_message, sig, key$public)
#'
verify_dilithium <- function(msg, signature, public_key) {

  msg <- msg_to_integer(msg)

  if (!inherits(signature, "pqcrypto_signature")) {
    stop("'signature' parameter does not have the expected class.")
  }

  if (!inherits(public_key, "public_key")) {
    stop("'public_key' parameter does not have the expected class.")
  }

  if (attr(public_key, "key_type") != "dilithium") {
    stop("Wrong public key type. Make sure you are using a 'Dilithium' public key.")
  }

  result <- cpp_verify_dilithium(signature, msg, public_key)
  result <- !as.logical(result)

  print(result)
  invisible(result)
}
