
#' Digital Signature - Read
#'
#' Reads a digital signature from a binary file created by `write_signature()`.
#'
#' @param file_name  The file name to read.
#'
#' @return a Digital signature read from the file
#' @export
#'
#' @examples
#' key <- keygen_dilithium(2)
#' important_message <- "Hello world!!"
#' signature <- sign_dilithium(key$private, important_message)
#' fname <- write_signature(signature)
#'
#' signature2 <- read_signature(fname)
#' identical(signature, signature2)
#'
read_signature <- function(file_name = NULL) {

  if(!file.exists(file_name)) {
    pq_stop(c(x = "Invalid 'file_name'."))
  }

  sign_der <- readBin(file_name, raw(), 1E6)

  struct <- PKI::ASN1.decode(sign_der)

  sig <- list()
  sig$version <- as.integer(struct[[1]])

  d_algo <- PKI::ASN1.decode(struct[[2]])
  sig$digest_algorithms <- as.character(PKI::as.oid(d_algo))

  eci <- c(PKI::ASN1.decode(struct[[3]][[2]]))
  attr(eci, "content_type") <- as.character(PKI::as.oid(struct[[3]][[1]]))
  class(eci) <- "pqcrypto_cms_id_data"
  sig$encap_content_info <- eci

  sig_infos <- PKI::ASN1.decode(struct[[4]])

  sinfo <- list()
  sinfo$version <- as.integer(sig_infos[[1]])

  sinfo$sid <- c(PKI::ASN1.decode(sig_infos[[2]]))

  sinfo$digest_algorithm <- as.character(PKI::as.oid(sig_infos[[3]]))

  sa <- PKI::ASN1.decode(sig_infos[[4]])
  sa1 <- PKI::ASN1.decode(sa[1:(2+as.integer(sa[2]))])
  sa <- sa[-1:-(2+as.integer(sa[2]))]
  sa2 <- PKI::ASN1.decode(sa[1:(2+as.integer(sa[2]))])
  sa3 <- PKI::ASN1.decode(sa[-1:-(2+as.integer(sa[2]))])
  sa1_l <- list(as.character(PKI::as.oid(sa1[[1]])), as.character(PKI::as.oid(sa1[[2]])))
  sa2_l <- list(as.character(PKI::as.oid(sa2[[1]])), c(sa2[[2]]))
  class(sa2_l[[2]]) <- c("hash", "sha3-512")
  ts <- as.POSIXct(rawToChar(sa3[[2]]), format = "%y%m%d%H%M%SZ", tz="UTC")
  sa3_l <- list(as.character(PKI::as.oid(sa3[[1]])),
                structure(strftime(ts, "%Y-%m-%dT%H:%M:%SZ", tz="UTC"),
                          unix_ts = as.integer(ts),
                          class = "pqcrypto_timestamp"))
  sinfo$signed_attrs <- list(sa1_l, sa2_l, sa3_l)
  class(sinfo$signed_attrs) <- "pqcrypto_cms_signed_attrs"

  sinfo$signature_algorithm <- as.character(PKI::as.oid(sig_infos[[5]]))

  sinfo$signature <- c(sig_infos[[6]])

  ua <- PKI::ASN1.decode(PKI::ASN1.decode(sig_infos[[7]]))
  sinfo$unsigned_attrs <- list(list(as.character(PKI::as.oid(ua[[1]])),
                                    structure(c(ua[[2]]),
                                              class = "pqcrypto_tsp_tsr")))
  class(sinfo$unsigned_attrs) <- "pqcrypto_cms_unsigned_attrs"
  class(sinfo) <- "pqcrypto_cms_signature_info"

  sig$signer_infos <- sinfo
  attr(sig, "content_type") <- "1.2.840.113549.1.7.2"
  class(sig) <- "pqcrypto_cms_id_signed_data"

  invisible(sig)
}
