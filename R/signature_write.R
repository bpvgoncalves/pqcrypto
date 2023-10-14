
write_signature <- function(sign, path = tempfile()) {

  sign_der <- as.der(sign)
  writeBin(sign_der, path)

  pq_msg(c(i=paste0("Signature written to: ", path)))
  invisible(path)
}
