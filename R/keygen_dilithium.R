

#' Dilithium Key Generation
#'
#' @param version  Type of key to be generated. Use 2 for Dilithium2, 3 for Dilithium3
#' or 5 for Dilithium5.
#'
#' @return A `keypair` object.
#' @export
#'
#' @examples
#' key <- keygen_dilithium()
#' key$key_type
#'
keygen_dilithium <- function(version=2) {


  key <- cpp_keygen_dilithium2()

  keypair <- list(key_type = "dilithium",
                  parameters = version,
                  private = structure(key[[1]],
                                      key_type = "dilithium",
                                      param = version,
                                      class="private_key"),
                  public = structure(key[[2]],
                                     key_type="dilithium",
                                     param = version,
                                     class="public_key"))
  class(keypair) <- c("keypair", "dilithium")

  rm(key)
  return(keypair)
}
