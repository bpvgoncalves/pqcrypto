
#' Key Management - Save
#'
#' Saves a key-pair, a private key or a public key as a text file.
#' **NOTE**: While the text file resembles a PEM encoded key, current implementation is not strictly
#' following RFC7468 (Textual Encodings of PKIX, PKCS, and CMS Structures), RFC5280 (Internet X.509
#' Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile) and RFC5958
#' (Asymmetric Key Packages).
#'
#' @param key       A key-pair produced by `keygen_kyber()`, `keygen_dilithium()` or
#'    `keygen_sphincs()`, or a private key or public key belonging to such a key-pair.
#' @param path      A path where the text file(s) containing the key(s) should be saved.
#'    Defaults to the temporary directory. If NULL, the resulting encoded key is printed to the
#'    console.
#' @param password  A password to be used for private key encryption. If not provided, which is
#'    **not advisable** when saving private keys (or the full key-pair) because the private key will
#'    not be encrypted which is **potentially unsafe**.
#'
#' @return Invisibly the encoded key. Saves it to a file or displays it on the console.
#'
#' @export
#'
#' @examples
#' key <- keygen_sphincs()
#' write_key(key$public, NULL)   # NULL used here to force console output instead of file saving
#'
write_key <- function(key, path = tempdir(), password = NULL) {

  public <- function(k) {
    paste0("-----BEGIN PUBLIC KEY-----\n",
           openssl::base64_encode(as.der(k), TRUE),
           "-----END PUBLIC KEY-----\n")
  }

  private <- function(k) {
    paste0("-----BEGIN PRIVATE KEY-----\n",
           openssl::base64_encode(as.der(k), TRUE),
           "-----END PRIVATE KEY-----\n")
  }

  private_enc <- function(k, password) {
    enc <- openssl::aes_cbc_encrypt(as.der(k), key_from_pass(as.character(password)))
    class(enc) <- "pqcrypto_encrypted_private_key"

    paste0("-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
           openssl::base64_encode(as.der(enc), TRUE),
           "-----END ENCRYPTED PRIVATE KEY-----\n")
  }

  if(!is.null(path) && !dir.exists(path)) {
    pq_stop(c(x = "Unable to find the specified 'path' to write into."))
  }

  if (inherits(key, "pqcrypto_keypair")) {
    if (!is.null(password)) {
      cert_prv <- private_enc(key$private, as.character(password))
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
    if (!is.null(password)) {
      cert_prv <- private_enc(key, password)
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

