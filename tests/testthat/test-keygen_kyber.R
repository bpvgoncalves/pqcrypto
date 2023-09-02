
test_that("Keys generation", {

  k <- keygen_kyber(512)

  expect_s3_class(k, "keypair")
  expect_equal(length(k$private), 1632)
  expect_equal(length(k$public), 800)

})
