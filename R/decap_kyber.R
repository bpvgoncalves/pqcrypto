

#' Title
#'
#' @param sk  Receiver's secret key
#' @param ct  Cipher text
#'
#' @return
#' @export
#'
#' @examples
decap_kyber <- function(sk, ct) {

  out <- cpp_decap_kyber512(sk, ct)
  return(out)
}
