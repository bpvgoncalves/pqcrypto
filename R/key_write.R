
#' Title
#'
#' @param key
#' @param pass
#'
#' @return
#' @export
#'
#' @examples
write_key <- function(key, pass = NULL) {

  public <- function(k) {
    if (requireNamespace("openssl", quietly = TRUE)) {
      base64text <- openssl::base64_encode(serialize(k, NULL), TRUE)
    } else if (requireNamespace("base64enc", quietly = TRUE)) {
      base64text <- base64enc::base64encode(serialize(k, NULL), 64, "\n")
    } else {
      pq_msg(x="Unable to write public key if openssl or base64enc packages are not present.")
      return(NULL)
    }
    paste0("-----BEGIN PUBLIC KEY-----\n",
           base64text, "\n",
           "-----END PUBLIC KEY-----\n")
  }

  private <- function(k) {
    paste0("-----BEGIN PRIVATE KEY-----\n",
           base64enc::base64encode(serialize(k, NULL), 64, "\n"), "\n",
           "-----END PRIVATE KEY-----\n")
  }

  private_enc <- function(k, pass) {
    enc <- openssl::aes_cbc_encrypt(serialize(k, NULL), openssl::sha256(charToRaw(pass)))
    paste0("-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
           base64enc::base64encode(enc, 64, "\n"), "\n",
           "-----END ENCRYPTED PRIVATE KEY-----\n")
  }


  if (inherits(key, "pqcrypto_keypair")) {
    if (!is.null(pass)) {
      cert_prv <- private_enc(key$private, as.character(pass))
    } else {
      cert_prv <- private(key$private)
    }
    cert_pub <- public(key$public)

    cat(cert_prv, "\n", cert_pub, sep = "")


  } else if (inherits(key, "pqcrypto_private_key")) {
    if (!is.null(pass)) {
      cert_prv <- private_enc(key, pass)
    } else {
      cert_prv <- private(key)
    }
    cat(cert_prv)
    invisible(cert_prv)


  } else if (inherits(key, "pqcrypto_public_key")) {
    cert_pub <- public(key)
    cat(cert_pub)
    invisible(cert_pub)

  } else {
    pq_stop("Invalid object type.")
  }

}

