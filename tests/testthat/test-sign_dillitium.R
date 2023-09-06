test_that("Dilithium2 digital signature", {

  key <- keygen_dilithium(2)
  important_message <- "Hello world!!"
  sig <- sign_dilithium(key$private, important_message)

  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "dilithium")
  expect_equal(length(sig), 2420)
})

test_that("Dilithium3 digital signature", {

  key <- keygen_dilithium(3)
  important_message <- "Hello world!!"
  sig <- sign_dilithium(key$private, important_message)

  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "dilithium")
  expect_equal(length(sig), 3309)
})

test_that("Dilithium5 digital signature", {

  key <- keygen_dilithium(5)
  important_message <- "Hello world!!"
  sig <- sign_dilithium(key$private, important_message)

  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "dilithium")
  expect_equal(length(sig), 4627)
})
