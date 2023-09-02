

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
