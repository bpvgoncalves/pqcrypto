
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
