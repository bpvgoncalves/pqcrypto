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
#' @useDynLib pqcrypto, .registration = TRUE
## usethis namespace: end
NULL


#' @export
print.pqcrypto_keypair <- function(x, ...) {
  cli::cli_h3("pqcrypto - Key-Pair")
  cli::cli_bullets(paste0(" Private Key Algorithm: ",
                          object_mapper(x$private$algorithm),
                          " (", x$private$algorithm, ")"))
}

#' @export
print.pqcrypto_private_key <- function(x, ...) {
  cli::cli_h3("pqcrypto - Private Key")
  cli::cli_bullets(paste0(" Algorithm: ",
                          object_mapper(x$algorithm),
                          " (", x$algorithm, ")"))
}

#' @export
print.pqcrypto_public_key <- function(x, ...) {
  cli::cli_h3("pqcrypto - Public Key")
  cli::cli_bullets(paste0(" Algorithm: ",
                          object_mapper(x$algorithm),
                          " (", x$algorithm, ")"))
}

#' @export
print.pqcrypto_shared_secret <- function(x, ...) {
  if (requireNamespace("cli", quietly = TRUE)) {
    cli::cli_h3("pqcrypto - Shared Secret")
  } else {
    message(paste0("-- pqcrypto - Shared Secret\n"))
  }
}

#' @export
print.pqcrypto_signature <- function(x, ...) {
  if (requireNamespace("cli", quietly = TRUE)) {
    cli::cli_h3("pqcrypto - Digital Signature")
    cli::cli_bullets(paste0("Algorithm:  ", attr(x, "algorithm")))
  } else {
    message(paste0("\n-- pqcrypto - Digital Signature\n",
                   "Algorithm: ", attr(x, "algorithm")))
  }
}
