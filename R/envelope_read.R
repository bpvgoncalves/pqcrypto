#' Envelope - Read
#'
#' Reads an envelope from a binary file created by `write_envelope()`.
#'
#' @param file_name  The file name to read.
#'
#' @return An envelope read from the file
#' @export
#'
#' @examples
#' key <- keygen_kyber(512)
#' env <- envelope_create("Very important message.", key$public)
#' fn <- write_envelope(env)
#'
#' env2 <- read_envelope(fn)
#' identical(env, env2)
#'
read_envelope <- function(file_name = NULL) {

  if(!file.exists(file_name)) {
    pq_stop(c(x = "Invalid 'file_name'."))
  }

  env_der <- readBin(file_name, raw(), 1E6)

  struct <- PKI::ASN1.decode(env_der)

  env <- list()
  env$version <- as.integer(struct[[1]])

  rec_info <- PKI::ASN1.decode(struct[[2]])
  r_info <- list()
  r_info$version <- as.integer(rec_info[[1]])
  r_info$rid <- c(PKI::ASN1.decode(rec_info[[2]]))
  r_info$encryption_algo <- as.character(PKI::as.oid(rec_info[[3]]))
  r_info$encrypted_key <- c(rec_info[[4]])
  class(r_info$encrypted_key) <- "pqcrypto_encapsulation"
  class(r_info) <- "pqcrypto_cms_key_transport_recipient"
  env$recipient_infos <- r_info

  eci <- list()
  eci$content_type <- as.character(PKI::as.oid(struct[[3]][[1]]))
  eci$content_encryption_algorithm$oid <- as.character(PKI::as.oid(struct[[3]][[2]][[1]]))
  eci$content_encryption_algorithm$param_iv <- c(struct[[3]][[2]][[2]])
  eci$encrypted_content <- c(struct[[3]][[3]])
  class(eci) <- "pqcrypto_cms_encrypted_content"
  env$encrypted_content_info <- eci

  attr(env, "content_type") <- "1.2.840.113549.1.7.3"
  class(env) <- "pqcrypto_cms_id_enveloped_data"

  invisible(env)
}
