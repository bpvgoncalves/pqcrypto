# Deprecated functions. To be removed in the future.

test_that("kyber-512 decapsulation works", {

  expect_snapshot(key <- keygen_kyber(512))
  expect_snapshot(ss1 <- encap_kyber(key$public))
  expect_snapshot(ss2 <- decap_kyber(ss1$encapsulation, key$private))
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  withr::local_options(lifecycle_verbosity = "quiet")
  expect_error(decap_kyber(ss$encapsulation, key$public))

  # encapsulation gets changed
  transmission_error <- as.raw(runif(768, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decap_kyber(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decap_kyber(bad_encapsulation, key$private))
})


test_that("kyber-768 decapsulation works", {
  expect_snapshot(key <- keygen_kyber(768))
  expect_snapshot(ss1 <- encap_kyber(key$public))
  expect_snapshot(ss2 <- decap_kyber(ss1$encapsulation, key$private))
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  withr::local_options(lifecycle_verbosity = "quiet")
  expect_error(decap_kyber(ss$encapsulation, key$public))

  transmission_error <- as.raw(runif(1088, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decap_kyber(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decap_kyber(bad_encapsulation, key$private))
})

test_that("kyber-1024 decapsulation works", {
  expect_snapshot(key <- keygen_kyber(1024))
  expect_snapshot(ss1 <- encap_kyber(key$public))
  expect_snapshot(ss2 <- decap_kyber(ss1$encapsulation, key$private))
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  withr::local_options(lifecycle_verbosity = "quiet")
  expect_error(decap_kyber(ss$encapsulation, key$public))

  transmission_error <- as.raw(runif(1568, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decap_kyber(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decap_kyber(bad_encapsulation, key$private))
})

test_that("kyber-x decapsulation fails on wrong parameter", {
  withr::local_options(lifecycle_verbosity = "quiet")
  key <- keygen_kyber(512)
  ss <- encap_kyber(key$public)

  # Bad key
  expect_error(decap_kyber(ss$encapsulation, "not_a_key"))

  # wrong family
  manipulated_key <- key
  attr(manipulated_key$private, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.0"
  expect_error(decap_kyber(ss$encapsulation, manipulated_key$private))

  invalid_key_algo <- keygen_dilithium()
  expect_error(decap_kyber(ss$encapsulation, invalid_key_algo$private))  # invalid algorithm

  # undefined algorithm, on the right 'family'
  manipulated_key <- key
  attr(manipulated_key$private, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.1.1.99"
  expect_error(decap_kyber(ss$encapsulation, manipulated_key$private))

  # Bad encapsulation
  bad_encapsulation <- as.integer(runif(768, 0, 256))   # wrong type, right size
  expect_error(decap_kyber(bad_encapsulation, key$private))

  bad_encapsulation <- as.integer(runif(1234, 0, 256))  # wrong type, wrong size
  expect_error(decap_kyber(bad_encapsulation, key$private))

  class(bad_encapsulation) <- "pqcrypto_encapsulation"  # right type, wrong size
  expect_error(decap_kyber(bad_encapsulation, key$private))
})
