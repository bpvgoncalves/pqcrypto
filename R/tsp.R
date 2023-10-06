
get_timestamp_secure <- function(tsq) {

  if (requireNamespace("httr2", quietly = TRUE)) {
    dertsq <- as.der(tsq)
    req <- httr2::request("https://freetsa.org/tsr")
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_body_raw(req, dertsq, "application/timestamp-query")

    resp <- httr2::req_perform(req)

    tsr <- PKI::ASN1.decode(resp$body)
    ts <- PKI::ASN1.decode(PKI::ASN1.decode(PKI::ASN1.decode(tsr[[2]][[2]])[[3]][[2]]))[[5]]
    ts <- as.POSIXct(rawToChar(ts), format = "%Y%m%d%H%M%SZ", tz="UTC")

    out <- list(ts = structure(strftime(ts, "%Y-%m-%dT%H:%M:%SZ", tz="UTC"),
                               unix_ts = as.integer(ts),
                               class = "pqcrypto_timestamp"),
                tsr = structure(resp$body,
                                class = "pqcrypto_tsp_tsr"))
  } else {
    out <- list(ts = get_timestamp(),
                tsr = NULL)
  }

  invisible(out)
}