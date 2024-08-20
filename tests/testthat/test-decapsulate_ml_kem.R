

test_that("ML-KEM-512 decapsulation works", {
  key <- keygen_ml_kem(512)
  ss1 <- encapsulate_ml_kem(key$public)
  ss2 <- decapsulate_ml_kem(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  expect_error(decapsulate_ml_kem(ss$encapsulation, key$public))

  # encapsulation gets changed
  transmission_error <- as.raw(runif(768, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decapsulate_ml_kem(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))
})


test_that("ML-KEM-768 decapsulation works", {
  key <- keygen_ml_kem(768)
  ss1 <- encapsulate_ml_kem(key$public)
  ss2 <- decapsulate_ml_kem(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  expect_error(decapsulate_ml_kem(ss$encapsulation, key$public))

  transmission_error <- as.raw(runif(1088, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decapsulate_ml_kem(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))
})

test_that("ML-KEM-1024 decapsulation works", {
  key <- keygen_ml_kem(1024)
  ss1 <- encapsulate_ml_kem(key$public)
  ss2 <- decapsulate_ml_kem(ss1$encapsulation, key$private)
  expect_equal(length(ss2), 32)
  expect_identical(ss1$shared_secret, ss2)

  # bad key
  expect_error(decapsulate_ml_kem(ss$encapsulation, key$public))

  transmission_error <- as.raw(runif(1568, 0, 256))
  class(transmission_error) <- "pqcrypto_encapsulation"
  expect_false(identical(decapsulate_ml_kem(transmission_error, key$private),
                         ss1$shared_secret))

  # mismatching sizes
  bad_encapsulation <- as.integer(runif(888, 0, 256))
  class(bad_encapsulation) <- "pqcrypto_encapsulation"
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))
})

test_that("ML-KEM-x decapsulation fails on wrong parameter", {
  key <- keygen_ml_kem(512)
  ss <- encapsulate_ml_kem(key$public)

  # Bad key
  expect_error(decapsulate_ml_kem(ss$encapsulation, "not_a_key"))

  # wrong family
  manipulated_key <- key
  attr(manipulated_key$private, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.0"
  expect_error(decapsulate_ml_kem(ss$encapsulation, manipulated_key$private))

  invalid_key_algo <- keygen_dilithium()
  expect_error(decapsulate_ml_kem(ss$encapsulation, invalid_key_algo$private))  # invalid algorithm

  # undefined algorithm, on the right 'family'
  manipulated_key <- key
  attr(manipulated_key$private, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.1.1.99"
  expect_error(decapsulate_ml_kem(ss$encapsulation, manipulated_key$private))

  # Bad encapsulation
  bad_encapsulation <- as.integer(runif(768, 0, 256))   # wrong type, right size
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))

  bad_encapsulation <- as.integer(runif(1234, 0, 256))  # wrong type, wrong size
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))

  class(bad_encapsulation) <- "pqcrypto_encapsulation"  # right type, wrong size
  expect_error(decapsulate_ml_kem(bad_encapsulation, key$private))
})
