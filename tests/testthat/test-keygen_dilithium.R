test_that("Dilithium2 keys generation", {

  k <- keygen_dilithium(2)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 2560)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 1312)
})

test_that("Dilithium3 keys generation", {

  k <- keygen_dilithium(3)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 4032)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 1952)
})

test_that("Dilithium5 keys generation", {

  k <- keygen_dilithium(5)
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 4896)
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 2592)
})

test_that("Keys generation fails on wrong parameters", {

  expect_error(keygen_dilithium(7))
  expect_error(keygen_dilithium(NULL))
  expect_error(keygen_dilithium(NA))
  expect_error(keygen_dilithium("invalid_param"))
})
