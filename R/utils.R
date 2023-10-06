
msg_to_raw <- function(msg) {
  serialize(msg, NULL)
}


#' Custom stop and message functions
#'
#' Make use of cli package, when available, for prettier console output, or use
#' R base functions otherwise.
#'
#' @param m    message to be printed
#'
#' @noRd
pq_stop <- function(m) {
  cli::cli_abort(m)
}

pq_msg <- function(m) {
  cli::cli_bullets(m)
  invisible(m)
}

key_from_pass <- function(x) {
  s <- as.raw(c(45, 154, 142, 227, 66, 149, 110, 187, 218, 36, 193, 244, 104, 167, 226, 3,
                163, 47, 127, 138, 220, 134, 248, 202, 192, 76, 237, 95, 79, 224, 44, 214))
  p <- charToRaw(x)
  for (i in 1:10000) {
    p <- openssl::sha3(p, 512, s)
  }
  openssl::sha3(p, 256)
}

get_timestamp <- function() {

  uts <- as.numeric(Sys.time())
  ts <- strftime(uts, "%Y-%m-%dT%H:%M:%OS3Z", tz="UTC")
  attr(ts, "unix_ts") <- uts
  class(ts) <- "pqcrypto_timestamp"

  invisible(ts)
}

object_mapper <- function(x) {

  # Own OID obtained from https://freeoid.pythonanywhere.com for pqcrypto package
  # Root OID:  1.3.6.1.4.1.54392.5.1859
  #            1.3.6.1.4.1.54392.5.1859.0       - Reserved
  #            1.3.6.1.4.1.54392.5.1859.1       - Algorithms
  #            1.3.6.1.4.1.54392.5.1859.1.1     - Algorithms - Kyber Family
  mapper <- c("1.3.6.1.4.1.54392.5.1859.1.1.1"  = c("Kyber 256"),
              "1.3.6.1.4.1.54392.5.1859.1.1.2"  = c("Kyber 768"),
              "1.3.6.1.4.1.54392.5.1859.1.1.3"  = c("Kyber 1024"),
  #            1.3.6.1.4.1.54392.5.1859.1.2     - Algorithms - Dilithium Family
              "1.3.6.1.4.1.54392.5.1859.1.2.1"  = c("Dilithium 2"),
              "1.3.6.1.4.1.54392.5.1859.1.2.2"  = c("Dilithium 3"),
              "1.3.6.1.4.1.54392.5.1859.1.2.3"  = c("Dilithium 5"),
  #            1.3.6.1.4.1.54392.5.1859.1.3     - Algorithms - Sphincs+ Family
              "1.3.6.1.4.1.54392.5.1859.1.3.1"  = c("Sphincs+ SHA2-128-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.2"  = c("Sphincs+ SHAKE-128-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.3"  = c("Sphincs+ SHA2-128-F"),
              "1.3.6.1.4.1.54392.5.1859.1.3.4"  = c("Sphincs+ SHAKE-128-F"),
              "1.3.6.1.4.1.54392.5.1859.1.3.5"  = c("Sphincs+ SHA2-192-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.6"  = c("Sphincs+ SHAKE-192-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.7"  = c("Sphincs+ SHA2-192-F"),
              "1.3.6.1.4.1.54392.5.1859.1.3.8"  = c("Sphincs+ SHAKE-192-F"),
              "1.3.6.1.4.1.54392.5.1859.1.3.9"  = c("Sphincs+ SHA2-256-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.10" = c("Sphincs+ SHAKE-256-S"),
              "1.3.6.1.4.1.54392.5.1859.1.3.11" = c("Sphincs+ SHA2-256-F"),
              "1.3.6.1.4.1.54392.5.1859.1.3.12" = c("Sphincs+ SHAKE-256-F")
  #            ....
  )
  mapper[x]
}

as.cms_data <- function(data) {

  raw_data <- serialize(data, NULL)
  attr(raw_data, "content_type") <- "1.2.840.113549.1.7.1"
  class(raw_data) <- "pqcrypto_cms_id_data"

  invisible(raw_data)
}

as.cms_signature_info <- function(private_key, signed_attrs, dig_signature) {

  s_info <- list(version = 3L,
                 sid = attr(private_key, "key_id"),
                 digest_algorithm = "2.16.840.1.101.3.4.2.10",
                 signed_attrs = signed_attrs,
                 signature_algorithm = attr(private_key, "algorithm"),
                 signature = dig_signature)
  class(s_info) <- "pqcrypto_cms_signature_info"

  invisible(s_info)
}

as.cms_signed_data <- function(content, s_info) {

  signed_data <- list(version = 3L,
                      digest_algorithms = s_info$digest_algorithm,
                      encap_content_info = content,
                      signer_infos = s_info)
  attr(signed_data, "content_type") <- "1.2.840.113549.1.7.2"
  class(signed_data) <- "pqcrypto_cms_id_signed_data"

  invisible(signed_data)
}

as.cms_encrypted_content <- function(content, encrypt_key) {

  content_enc <- openssl::aes_cbc_encrypt(content, encrypt_key)

  enc_content <- list(content_type = attr(content, "content_type"),
                      content_encryption_algorithm = list(oid = "2.16.840.1.101.3.4.1.42",
                                                          param_iv = attr(content_enc, "iv")),
                      encryptedContent = c(content_enc))
  class(enc_content) <- "pqcrypto_cms_encrypted_content"

  invisible(enc_content)
}

as.cms_key_transport_recipient <- function(public_key, encap_key) {

  key_transport <- list(version = 2L,
                        rid = unclass(openssl::sha3(public_key, 224)),
                        encryption_algo = attr(public_key, "algorithm"),
                        encrypted_key = encap_key)
  class(key_transport) <- "pqcrypto_cms_key_transport_recipient"

  invisible(key_transport)
}

as.cms_enveloped_data <- function(message, public_key) {

  data <- as.cms_data(message)

  encap_key <- encap_kyber(public_key)

  encrypted_content <- as.cms_encrypted_content(data, encap_key$shared_secret)
  r_info<- as.cms_key_transport_recipient(public_key, encap_key$encapsulation)

  env <- list(version = 2L,
              recipient_infos = r_info,
              encrypted_content_info = encrypted_content)
  attr(env, "content_type") <- "1.2.840.113549.1.7.3"
  class(env) <- "pqcrypto_cms_id_enveloped_data"

  invisible(env)
}

as.tsp_tsq <- function(data) {

  tsr <- list(version = 1L,
              message_imprint = list(algo = "2.16.840.1.101.3.4.2.3",
                                     hash = openssl::sha2(data, 512)))
  class(tsr) <- "pqcrypto_tsp_tsq"

  invisible(tsr)
}
