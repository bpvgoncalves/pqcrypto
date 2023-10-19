
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

  dt <- as.POSIXlt(attr(ts, "unix_ts"), tz="UTC", origin = "1970-01-01")
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
  version <- PKI::ASN1.encode(PKI::ASN1.item(version, 160L))

  algorithm <- PKI::ASN1.encode(PKI::as.oid(attr(k, "algorithm")))
  parameters <- as.der(NULL)
  algorithm_identifier <- PKI::ASN1.encode(PKI::ASN1.item(c(algorithm, parameters), 48L))

  private_key <- PKI::ASN1.encode(PKI::ASN1.item(k, 4L))

  ext_id <- PKI::ASN1.encode(PKI::as.oid("2.5.29.14"))
  ext_crit <- as.der(FALSE)
  ext_value <- PKI::ASN1.encode(PKI::ASN1.item(attr(k, "key_id"), 4L))
  extension <- PKI::ASN1.encode(PKI::ASN1.item(c(ext_id, ext_crit, ext_value), 48L))
  extensions <- PKI::ASN1.encode(PKI::ASN1.item(extension, 48L))
  extensions <- PKI::ASN1.encode(PKI::ASN1.item(extensions, 163L))

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

  sa <- PKI::ASN1.encode(PKI::ASN1.item(c(attr1, attr2, attr3), 49L))
  PKI::ASN1.encode(PKI::ASN1.item(sa, 160L))
}

as.der.pqcrypto_cms_unsigned_attrs <- function(ua) {

  attr1_type <- PKI::ASN1.encode(PKI::as.oid(ua[[1]][[1]]))
  attr1_value <- PKI::ASN1.encode(PKI::ASN1.item(ua[[1]][[2]], 4L))
  attr1 <- PKI::ASN1.encode(PKI::ASN1.item(c(attr1_type, attr1_value), 48L))

  ua <- PKI::ASN1.encode(PKI::ASN1.item(attr1, 49L))
  PKI::ASN1.encode(PKI::ASN1.item(ua, 161L))
}

as.der.pqcrypto_cms_signature_info <- function(si) {

  ver <- PKI::ASN1.encode(PKI::ASN1.item(si$version, 2L))
  sid <- PKI::ASN1.encode(PKI::ASN1.item(si$sid, 4L))
  sid <- PKI::ASN1.encode(PKI::ASN1.item(sid, 160L))
  d_algo <- PKI::ASN1.encode(PKI::as.oid(si$digest_algorithm))
  sa <- as.der(si$signed_attrs)
  s_algo <- PKI::ASN1.encode(PKI::as.oid(si$signature_algorithm))
  s <- PKI::ASN1.encode(PKI::ASN1.item(si$signature, 4L))
  ua <- as.der(si$unsigned_attrs)

  PKI::ASN1.encode(PKI::ASN1.item(c(ver, sid, d_algo, sa, s_algo, s, ua), 48L))
}

as.der.pqcrypto_cms_id_signed_data <- function(sd) {

  ver <- PKI::ASN1.encode(PKI::ASN1.item(sd$version, 2L))
  d_algo <- PKI::ASN1.encode(PKI::as.oid(sd$digest_algorithm))
  d_algo <- PKI::ASN1.encode(PKI::ASN1.item(d_algo, 49L))

  eci_type <- PKI::ASN1.encode(PKI::as.oid(attr(sd$encap_content_info, "content_type")))
  eci_value <- PKI::ASN1.encode(PKI::ASN1.item(sd$encap_content_info, 4L))
  eci_value <- PKI::ASN1.encode(PKI::ASN1.item(eci_value, 160L))
  eci <- PKI::ASN1.encode(PKI::ASN1.item(c(eci_type, eci_value), 48L))

  si <- as.der(sd$signer_infos)
  si <- PKI::ASN1.encode(PKI::ASN1.item(si, 49L))

  PKI::ASN1.encode(PKI::ASN1.item(c(ver, d_algo, eci, si), 48L))
}

as.der.pqcrypto_cms_id_enveloped_data <- function(e) {

  ver <- PKI::ASN1.encode(PKI::ASN1.item(e$version, 2L))

  ri_ver <- PKI::ASN1.encode(PKI::ASN1.item(e$recipient_infos$version, 2L))
  ri_rid <- PKI::ASN1.encode(PKI::ASN1.item(e$recipient_infos$rid, 4L))
  ri_rid <- PKI::ASN1.encode(PKI::ASN1.item(ri_rid, 160L))
  ri_kea <- PKI::ASN1.encode(PKI::as.oid(e$recipient_infos$encryption_algo))
  ri_ek <- PKI::ASN1.encode(PKI::ASN1.item(e$recipient_infos$encrypted_key, 4L))
  ri <- PKI::ASN1.encode(PKI::ASN1.item(c(ri_ver, ri_rid, ri_kea, ri_ek), 48L))
  ri <- PKI::ASN1.encode(PKI::ASN1.item(ri, 49L))

  eci_l <- e$encrypted_content_info
  eci_ct <-  PKI::ASN1.encode(PKI::as.oid(eci_l$content_type))
  eci_cea_algo <- PKI::ASN1.encode(PKI::as.oid(eci_l$content_encryption_algorithm$oid))
  eci_cea_param <- PKI::ASN1.encode(PKI::ASN1.item(eci_l$content_encryption_algorithm$param_iv,
                                                   4L))
  eci_cea <- PKI::ASN1.encode(PKI::ASN1.item(c(eci_cea_algo, eci_cea_param), 48L))
  eci_ec <- PKI::ASN1.encode(PKI::ASN1.item(eci_l$encrypted_content, 128L))
  # eci_ec <- PKI::ASN1.encode(PKI::ASN1.item(eci_ec, 160L))
  eci <- PKI::ASN1.encode(PKI::ASN1.item(c(eci_ct, eci_cea, eci_ec), 48L))

  PKI::ASN1.encode(PKI::ASN1.item(c(ver, ri, eci), 48L))

}

as.der.pqcrypto_tsp_tsq <- function(t) {

  ver <- PKI::ASN1.encode(PKI::ASN1.item(t$version, 2L))

  algo <- PKI::ASN1.encode(PKI::as.oid(t$message_imprint$algo))
  algo <- PKI::ASN1.encode(PKI::ASN1.item(c(algo, as.der(NULL)), 48L))
  hash <- PKI::ASN1.encode(PKI::ASN1.item(t$message_imprint$hash, 4L))
  mi <- PKI::ASN1.encode(PKI::ASN1.item(c(algo, hash), 48L))

  PKI::ASN1.encode(PKI::ASN1.item(c(ver, mi), 48L))
}
