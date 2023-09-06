
#' Dilithium Digital Signature
#'
#' @param private_key The private key used for message signing.
#' @param msg         The message to be signed.
#'
#' @return A 'pqcrypto_signature' object.
#'
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' sig <- sign_dilithium(key$private, important_message)
#' sig[1:10]
#'
sign_dilithium <- function(private_key, msg) {

  if (!inherits(private_key, "private_key")) {
    stop("'private_key' parameter does not have the expected class.")
  }

  if (attr(private_key, "key_type") != "dilithium") {
    stop("Wrong private key type. Make sure you are using a 'Dilithium' private key.")
  }

  msg <- msg_to_integer(msg)

  dig_signature <- cpp_sign_dilithium(msg, private_key)
  attr(dig_signature, "algorithm") <- "dilithium"
  class(dig_signature) <- "pqcrypto_signature"
  dig_signature
}



msg_to_integer <- function(msg) {



  if (!is.raw(msg)) {

    if (length(msg) != 1) {
      stop("Unexpected non-scalar input 'msg'.")
    }

    if (is.null(msg) || is.na(msg) || is.nan(msg) || is.infinite(msg)) {
      stop("Message cannot be NULL, NA, NaN or INF.")
    }

    if (is.character(msg)) {
      msg <- charToRaw(msg)
    } else if (is.numeric(msg) || is.logical(msg)) {
      msg <- charToRaw(as.character(msg))
    } else {
      msg <- serialize(msg, NULL)
    }
  }

  as.integer(msg)
}
