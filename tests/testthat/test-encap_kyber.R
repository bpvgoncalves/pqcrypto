
test_that("kyber-512 encapsulation works", {
  key <- keygen_kyber(512)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_s3_class(ss$shared_secret, "pqcrypto_shared_secret")
  expect_equal(length(ss$shared_secret), 32)
  expect_s3_class(ss$encapsulation, "pqcrypto_encapsulation")
  expect_equal(length(ss$encapsulation), 768)
})


test_that("kyber-768 encapsulation works", {
  key <- keygen_kyber(768)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_s3_class(ss$shared_secret, "pqcrypto_shared_secret")
  expect_equal(length(ss$shared_secret), 32)
  expect_s3_class(ss$encapsulation, "pqcrypto_encapsulation")
  expect_equal(length(ss$encapsulation), 1088)
})

test_that("kyber-1024 encapsulation works", {
  key <- keygen_kyber(1024)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_s3_class(ss$shared_secret, "pqcrypto_shared_secret")
  expect_equal(length(ss$shared_secret), 32)
  expect_s3_class(ss$encapsulation, "pqcrypto_encapsulation")
  expect_equal(length(ss$encapsulation), 1568)
})

test_that("kyber-x encapsulation fails on wrong parameter", {
  key <- keygen_kyber(512)

  expect_error(encap_kyber("not_a_valid_parameter"))
  expect_error(encap_kyber(key$private))   # must be public!

  manipulated_key <- key
  manipulated_key$public$algorithm <- "1.3.6.1.4.1.54392.5.1859.0"
  expect_error(encap_kyber(manipulated_key$public))

  invalid_key_algo <- keygen_dilithium()
  expect_error(encap_kyber(invalid_key_algo$public))  # invalid algorithm
})
