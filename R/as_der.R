
as.der <- function(object, ...) {
  UseMethod("as.der")
}

as.der.NULL <- function(n) {
  # The contents octets shall not contain any octets.
  # NOTE – The length octet is zero.
  # -- ITU-T-RECOMENDATION-X.690-202102 (8.8.2)

  as.raw(c(5L, 0L))
}

as.der.logical <- function(l) {
  # If the encoding represents the boolean value TRUE, its single
  # contents octet shall have all eight bits set to one.
  # -- ITU-T-RECOMENDATION-X.690-202102 (11.1)

  if (l) {
    as.raw(c(1L, 1L, 255L))
  } else {
    as.raw(c(1L, 1L, 0L))
  }
}

as.der.pqcrypto_timestamp <- function (ts) {
  # CAs conforming to this profile MUST always encode certificate
  # validity dates through the year 2049 as  ; certificate validity
  # dates in 2050 or later MUST be encoded as GeneralizedTime.
  # -- RFC 5280

  dt <- as.POSIXlt(attr(ts, "unix_ts"), tz="UTC")
  if (dt$year <= 49 || dt$year >= 150) {
    # GeneralizedTime
    strdate <- strftime(dt, "%Y%m%d%H%M%SZ", tz="UTC")
    tag <- 24L
  } else {
    # UTCTime
    strdate <- strftime(dt, "%y%m%d%H%M%SZ", tz="UTC")
    tag <- 23L
  }

  PKI::ASN1.encode(PKI::ASN1.item(charToRaw(strdate), tag))
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

as.der.pqcrypto_cms_signed_attrs <- function(sa) {

  attr1_type <- PKI::ASN1.encode(PKI::as.oid(sa[[1]][[1]]))
  attr1_value <- PKI::ASN1.encode(PKI::as.oid(sa[[1]][[2]]))
  attr1 <- PKI::ASN1.encode(PKI::ASN1.item(c(attr1_type, attr1_value), 48L))

  attr2_type <- PKI::ASN1.encode(PKI::as.oid(sa[[2]][[1]]))
  attr2_value <- PKI::ASN1.encode(PKI::ASN1.item(sa[[2]][[2]], 4L))
  attr2 <- PKI::ASN1.encode(PKI::ASN1.item(c(attr2_type, attr2_value), 48L))

  attr3_type <- PKI::ASN1.encode(PKI::as.oid(sa[[3]][[1]]))
  attr3_value <- as.der(sa[[3]][[2]])
  attr3 <- PKI::ASN1.encode(PKI::ASN1.item(c(attr3_type, attr3_value), 48L))

  PKI::ASN1.encode(PKI::ASN1.item(c(attr1, attr2, attr3), 49L))
}
