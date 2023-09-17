
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
