

#' Title
#'
#' @param pk  Receiver's public key
#'
#' @return
#' @export
#'
#' @examples
encap_kyber <- function(pk) {

  out <- cpp_encap_kyber512(pk)
  return(out)
}
