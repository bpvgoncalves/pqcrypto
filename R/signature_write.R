
#' Digital Signature - Write
#'
#' Writes a digital signature as a binary file.
#'
#' @param signature  A digital signature produced by `sign_dilithium()` or by
#'    `sign_sphincs()`.
#' @param path  The file path. If not provided a file with a random name will
#'    be saved in the temporary folder.
#'
#' @return Invisibly, the file path
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' signature <- sign_dilithium(key$private, important_message)
#' write_signature(signature)
#'
write_signature <- function(signature, path = tempfile()) {

  if (!inherits(signature, "pqcrypto_cms_id_signed_data")) {
    pq_stop(c(x = "'signature' parameter does not have the expected class.",
              i = "'signature' must have `pqcrypto_cms_id_signed_data` class."))
  }

  sign_der <- as.der(signature)
  tryCatch({
    writeBin(sign_der, path)
  },
  condition = function(c){
    pq_stop(c$message, c$call)
  })

  pq_msg(c(i=paste0("Signature written to: ", path)))
  invisible(path)
}
