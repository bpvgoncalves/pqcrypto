
test_that("kyber-512 encapsulation works", {
  key <- keygen_kyber(512)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_equal(length(ss$shared_secret), 32)
  expect_equal(length(ss$encapsulation), 768)
})


test_that("kyber-768 encapsulation works", {
  key <- keygen_kyber(768)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_equal(length(ss$shared_secret), 32)
  expect_equal(length(ss$encapsulation), 1088)
})

test_that("kyber-1024 encapsulation works", {
  key <- keygen_kyber(1024)
  ss <- encap_kyber(key$public)
  expect_equal(length(ss), 2)
  expect_equal(length(ss$shared_secret), 32)
  expect_equal(length(ss$encapsulation), 1568)
})

test_that("kyber-x encapsulation fails on wrong parameter", {
  key <- keygen_kyber(512)

  expect_error(encap_kyber("not_a_valid_parameter"))
  expect_error(encap_kyber(key$private))   # must be public!
})
