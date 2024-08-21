# pqcrypto - Post-Quantum Cryptography
# Copyright (C) 2023  Bruno Gonçalves
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will .be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

## usethis namespace: start
#' @importFrom lifecycle deprecated
#' @useDynLib pqcrypto, .registration = TRUE
## usethis namespace: end
NULL

# Required for testthat mocking to work
requireNamespace <- NULL

#' @export
print.pqcrypto_keypair <- function(x, ...) {
  cli::cli_h3("pqcrypto - Key-Pair")
  cli::cli_bullets(paste0(" Private Key Algorithm: ",
                          object_mapper(attr(x$private, "algorithm")),
                          " (", attr(x$private, "algorithm"), ")"))
}

#' @export
print.pqcrypto_private_key <- function(x, ...) {
  cli::cli_h3("pqcrypto - Private Key")
  cli::cli_bullets(paste0(" Algorithm: ",
                          object_mapper(attr(x, "algorithm")),
                          " (", attr(x, "algorithm"), ")"))
}

#' @export
print.pqcrypto_public_key <- function(x, ...) {
  cli::cli_h3("pqcrypto - Public Key")
  cli::cli_bullets(paste0(" Algorithm: ",
                          object_mapper(attr(x, "algorithm")),
                          " (", attr(x, "algorithm"), ")"))
}

#' @export
print.pqcrypto_shared_secret <- function(x, ...) {
  cli::cli_h3("pqcrypto - Shared Secret")
}

#' @export
print.pqcrypto_cms_id_signed_data <- function(x, ...) {
  cli::cli_h3("pqcrypto - Digital Signature")
  cli::cli_bullets(paste0("Signature Algorithm:  ",
                          object_mapper(x$signer_infos$signature_algorithm),
                          " (", x$signer_infos$signature_algorithm, ")"))
}
