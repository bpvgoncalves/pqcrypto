
get_timestamp_secure <- function(tsq) {

  if (requireNamespace("httr2", quietly = TRUE)) {
    dertsq <- as.der(tsq)
    req <- httr2::request("https://freetsa.org/tsr")
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_body_raw(req, dertsq, "application/timestamp-query")

    try_resp <- try(httr2::req_perform(req), silent = TRUE)

    if (inherits(try_resp, "httr2_response")) {
      resp <- try_resp
    } else {
      resp <- NULL
    }
    if (!is.null(resp) && resp$status_code == 200L) {
      tsr <- PKI::ASN1.decode(resp$body)
      if (tsr[[1]][[1]] == 0) {
        # PKIStatus ::= INTEGER { granted (0), grantedWithMods (1), rejection (2), waiting (3),
        # revocationWarning (4), revocationNotification (5) }
        ts <- PKI::ASN1.decode(PKI::ASN1.decode(PKI::ASN1.decode(tsr[[2]][[2]])[[3]][[2]]))[[5]]
        ts <- as.POSIXct(rawToChar(ts), format = "%Y%m%d%H%M%SZ", tz = "UTC")

        out <- list(ts = structure(strftime(ts, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
                                   unix_ts = as.integer(ts),
                                   class = "pqcrypto_timestamp"),
                    tsr = structure(resp$body,
                                    class = "pqcrypto_tsp_tsr"))
      } else {
        pq_msg(c(i="Time stamp not granted by the TSA. Using system time."))
        out <- list(ts = get_timestamp(),
                    tsr = NULL)
      }
    } else {
      pq_msg(c(i="Invalid or no response from the TSA. Using system time."))
      out <- list(ts = get_timestamp(),
                  tsr = NULL)
    }
  } else {
    pq_msg(c(i="Pacakge 'httr2' not available. Using system time."))
    out <- list(ts = get_timestamp(),
                tsr = NULL)
  }

  invisible(out)
}
