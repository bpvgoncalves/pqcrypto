

test_that("kyber-512 decapsulation works", {
  key <- keygen_kyber(512)
  ss1 <- encap_kyber(key$public)
  ss2 <- decap_kyber(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)
})


test_that("kyber-768 decapsulation works", {
  key <- keygen_kyber(768)
  ss1 <- encap_kyber(key$public)
  ss2 <- decap_kyber(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)
})

test_that("kyber-1024 decapsulation works", {
  key <- keygen_kyber(1024)
  ss1 <- encap_kyber(key$public)
  ss2 <- decap_kyber(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)
})

test_that("kyber-x decapsulation fails on wrong parameter", {
  key <- keygen_kyber(512)
  ss <- encap_kyber(key$public)
  expect_error(decap_kyber(ss$encapsulation, "not_a_key"))
  expect_error(decap_kyber(ss$encapsulation, key$public))

  manipulated_key <- key
  attr(manipulated_key$private, "param") <- 1234
  expect_error(decap_kyber(ss$encapsulation, manipulated_key$private))

  invalid_key_algo <- keygen_dilithium()
  expect_error(decap_kyber(ss$encapsulation, invalid_key_algo$private))  # invalid algorithm

  bad_encapsulation <- as.integer(runif(768, 0, 256))  # wrong type, right size
  expect_error(decap_kyber(bad_encapsulation, key$private))

  bad_encapsulation <- as.integer(runif(1234, 0, 256))  # wrong type, wrong size
  expect_error(decap_kyber(bad_encapsulation, key$private))

  class(bad_encapsulation) <- "pqcrypto_encapsulation"  # right type, wrong size
  expect_error(decap_kyber(bad_encapsulation, key$private))

})
