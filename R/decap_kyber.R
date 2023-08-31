

#' Kyber shared secret/shared key encapsulation
#'
#' @param encapsulation  Received encapsulation object.
#' @param secret_key   Receiver's secret key
#'
#' @return The shared secret
#'
#' @export
#'
#' @examples
#'
decap_kyber <- function(encapsulation, secret_key) {

  if (attr(secret_key, "param") == 512) {
    out <- cpp_decap_kyber512(secret_key, encapsulation)
  } else if (attr(secret_key, "param") == 768) {
    out <- cpp_decap_kyber768(secret_key, encapsulation)
  } else if (attr(secret_key, "param") == 1024) {
    out <- cpp_decap_kyber1024(secret_key, encapsulation)
  } else {
    stop("Invalid encapsulation parameters.")
  }

  return(out)
}
