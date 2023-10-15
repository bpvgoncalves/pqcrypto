#' Envelope - Write
#'
#' @param envelope An envelope produced by `envelope_create()`.
#' @param path     The file path. If not provided a file with a random name will
#'    be saved in the temporary folder.
#'
#' @return Invisibly, the file path.
#' @export
#'
#' @examples
#' key <- keygen_kyber(512)
#' env <- envelope_create("Very important message.", key$public)
#' write_envelope(env)

write_envelope <- function(envelope, path = tempfile()) {

  if (!inherits(envelope, "pqcrypto_cms_id_enveloped_data")) {
    pq_stop(c(x = "'envelope' parameter does not have the expected class.",
              i = "'envelope' must have `pqcrypto_cms_id_enveloped_data` class."))
  }

  env_der <- as.der(envelope)
  tryCatch({
    writeBin(env_der, path)
  },
  condition = function(c){
    pq_stop(c$message, c$call)
  })

  pq_msg(c(i=paste0("Envelope written to: ", path)))
  invisible(path)
}
