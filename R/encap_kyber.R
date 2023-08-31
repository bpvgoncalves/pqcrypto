

#' Kyber shared secret/shared key encapsulation
#'
#' @param pub_key  Receiver's public key
#'
#' @return A secret key and its encapsulation to be shared with the owner of the used public key.
#'
#' @export
#'
#' @examples
#' key <- keygen_kyber(512)
#' s_s <- encap_kyber(key$public)  # This generates an encapsulation readable only by key$private
#'
encap_kyber <- function(pub_key) {


  if (attr(pub_key, "param") == 512) {
    out <- cpp_encap_kyber512(pub_key)
  } else if (attr(pub_key, "param") == 768) {
    out <- cpp_encap_kyber768(pub_key)
  } else if (attr(pub_key, "param") == 1024)  {
    out <- cpp_encap_kyber1024(pub_key)
  } else {
    stop("Unknown key parameters set.")
  }

  encap <- list(shared_secret = out[[2]],
                encapsulation = out[[1]])
  class(encap) <- c("encapsulation", "kyber")

  return(encap)
}
