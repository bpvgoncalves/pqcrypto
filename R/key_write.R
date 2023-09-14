
#' Title
#'
#' @param key
#' @param pass
#'
#' @return
#' @export
#'
#' @examples
write_key <- function(key, path = tempdir(), pass = NULL) {

  raw_to_b64 <- function(k) {
    if (requireNamespace("openssl", quietly = TRUE)) {
      base64text <- openssl::base64_encode(serialize(k, NULL), TRUE)
    } else if (requireNamespace("base64enc", quietly = TRUE)) {
      base64text <- paste0(base64enc::base64encode(serialize(k, NULL), 64, "\n"), "\n")
    } else {
      pq_msg(c(x="Unable to write keys to file if openssl or base64enc packages are not present."))
      return(NULL)
    }
    invisible(base64text)
  }

  public <- function(k) {
    paste0("-----BEGIN PUBLIC KEY-----\n",
           raw_to_b64(k),
           "-----END PUBLIC KEY-----\n")
  }

  private <- function(k) {
    paste0("-----BEGIN PRIVATE KEY-----\n",
           raw_to_b64(k),
           "-----END PRIVATE KEY-----\n")
  }

  private_enc <- function(k, pass) {
    if (requireNamespace("openssl", quietly = TRUE)) {
      enc <- openssl::aes_cbc_encrypt(serialize(k, NULL),
                                      openssl::sha256(charToRaw(pass)))
    } else {
      pq_msg(c(x="Private key encryption requires openssl package."))
      return(NULL)
    }
    paste0("-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
           raw_to_b64(enc),
           "-----END ENCRYPTED PRIVATE KEY-----\n")
  }

  if (inherits(key, "pqcrypto_keypair")) {
    if (!is.null(pass)) {
      cert_prv <- private_enc(key$private, as.character(pass))
    } else {
      cert_prv <- private(key$private)
    }
    cert_pub <- public(key$public)

    if (is.null(path)) {
      cat(cert_prv, "\n", cert_pub, sep = "")
    } else {
      ff <- file(paste0(path, "/keypair"), "wt")
      cat(cert_prv, file = ff)
      close(ff)
      ff <- file(paste0(path, "/keypair.pub"), "wt")
      cat(cert_pub, file = ff)
      close(ff)
    }

  } else if (inherits(key, "pqcrypto_private_key")) {
    if (!is.null(pass)) {
      cert_prv <- private_enc(key, pass)
    } else {
      cert_prv <- private(key)
    }
    if (is.null(path)) {
      cat(cert_prv)
    } else {
      ff <- file(paste0(path, "/keypair"), "wt")
      cat(cert_prv, file = ff)
      close(ff)
    }
    invisible(cert_prv)

  } else if (inherits(key, "pqcrypto_public_key")) {
    cert_pub <- public(key)
    if (is.null(path)) {
      cat(cert_pub)
    } else {
      ff <- file(paste0(path, "/keypair.pub"), "wt")
      cat(cert_pub, file = ff)
      close(ff)
    }
    invisible(cert_pub)

  } else {
    pq_stop("Invalid object type.")
  }

}

