test_that("ML-DSA-44 keys generation", {

  k <- keygen_ml_dsa(2)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 2560)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 1312)
})

test_that("ML-DSA-65 keys generation", {

  k <- keygen_ml_dsa(3)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 4032)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 1952)
})

test_that("ML-DSA-87 keys generation", {

  k <- keygen_ml_dsa(5)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 4896)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 2592)
})

test_that("Keys generation fails on wrong parameters", {

  expect_error(keygen_ml_dsa(7))
  expect_error(keygen_ml_dsa(NULL))
  expect_error(keygen_ml_dsa(NA))
  expect_error(keygen_ml_dsa("invalid_param"))
})
