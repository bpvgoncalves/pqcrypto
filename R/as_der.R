
as.der <- function(object, ...) {
  UseMethod("as.der")
}

as.der.NULL <- function(n) {
  as.raw(c(5L, 0L))
}

as.der.logical <- function(l) {
  if (l) {
    as.raw(c(1L, 1L, 255L))
  } else {
    as.raw(c(1L, 1L, 0L))
  }
}

as.der.pqcrypto_public_key <- function(k) {

  algorithm <- PKI::ASN1.encode(PKI::as.oid(attr(k, "algorithm")))
  parameters <- as.der(NULL)
  algorithm_identifier <- PKI::ASN1.encode(PKI::ASN1.item(c(algorithm, parameters), 48L))

  subject_public_key <- PKI::ASN1.encode(PKI::ASN1.item(k, 3L))

  PKI::ASN1.encode(PKI::ASN1.item(c(algorithm_identifier, subject_public_key), 48L))
}


as.der.pqcrypto_private_key <- function(k) {

  version <- PKI::ASN1.encode(PKI::ASN1.item(attr(k, "version"), 2L))

  algorithm <- PKI::ASN1.encode(PKI::as.oid(attr(k, "algorithm")))
  parameters <- as.der(NULL)
  algorithm_identifier <- PKI::ASN1.encode(PKI::ASN1.item(c(algorithm, parameters), 48L))

  private_key <- PKI::ASN1.encode(PKI::ASN1.item(k, 4L))

  ext_id <- PKI::ASN1.encode(PKI::as.oid("2.5.29.14"))
  ext_crit <- as.der(FALSE)
  ext_value <- PKI::ASN1.encode(PKI::ASN1.item(attr(k, "key_id"), 4L))
  extension <- PKI::ASN1.encode(PKI::ASN1.item(c(ext_id, ext_crit, ext_value), 48L))
  extensions <- PKI::ASN1.encode(PKI::ASN1.item(extension, 48L))

  PKI::ASN1.encode(PKI::ASN1.item(c(version, algorithm_identifier, private_key, extensions), 48L))
}


as.der.pqcrypto_encrypted_private_key <- function(enc_data) {

  algorithm <- PKI::ASN1.encode(PKI::as.oid("2.16.840.1.101.3.4.1.42"))
  parameters <- PKI::ASN1.encode(PKI::ASN1.item(attr(enc_data, "iv"), 4L))
  encryption_algorithm <- PKI::ASN1.encode(PKI::ASN1.item(c(algorithm, parameters), 48L))

  encrypted_data <- PKI::ASN1.encode(PKI::ASN1.item(enc_data, 4L))

  encrypted_private_key_info <- PKI::ASN1.encode(PKI::ASN1.item(c(encryption_algorithm,
                                                                  encrypted_data),
                                                                48L))
}
