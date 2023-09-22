
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
  if (requireNamespace("cli", quietly = TRUE)) {
    cli::cli_abort(m)
  } else {
    stop(paste(m, collapse = "\n"))
  }
}

pq_msg <- function(m) {
  if (requireNamespace("cli", quietly = TRUE)) {
    cli::cli_bullets(m)
  } else {
    message(paste(m, collapse = "\n"))
  }
  invisible(m)
}

key_from_pass <- function(x) {
  if (!requireNamespace("openssl", quietly = TRUE)) {
    pq_stop("This function requires the openssl package.")
  }
  s <- as.raw(c(45, 154, 142, 227, 66, 149, 110, 187, 218, 36, 193, 244, 104, 167, 226, 3,
                163, 47, 127, 138, 220, 134, 248, 202, 192, 76, 237, 95, 79, 224, 44, 214))
  p <- charToRaw(x)
  for (i in 1:10000) {
    p <- openssl::sha3(p, 512, s)
  }
  openssl::sha3(p, 256)
}

get_timestamp <- function() {
  strftime(Sys.time(), "%Y-%m-%dT%H:%M:%OS3Z", tz="UTC")
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
