
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
