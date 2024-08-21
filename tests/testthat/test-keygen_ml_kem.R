
test_that("Kyber-512 keys generation", {

  k <- keygen_ml_kem(512)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 1632)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 800)
})

test_that("Kyber-768 keys generation", {

  k <- keygen_ml_kem(768)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 2400)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 1184)
})

test_that("Kyber-1024 keys generation", {

  k <- keygen_ml_kem(1024)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 3168)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 1568)
})

test_that("Keys generation fails on wrong parameters", {

  expect_error(keygen_ml_kem(2048))
  expect_error(keygen_ml_kem(NULL))
  expect_error(keygen_ml_kem(NA))
  expect_error(expect_warning(keygen_ml_kem("invalid_param")))
})
