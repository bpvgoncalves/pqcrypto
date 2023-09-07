test_that("Digital signatures verification - Dilithium2", {

  key <- keygen_dilithium(2)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)

  expect_true(verify_dilithium(important_message, signature, key$public))

  expect_false(verify_dilithium("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != 0L) forged_signature[1] <- 0L else forged_signature[1] <- 255L
  expect_false(verify_dilithium(important_message, forged_signature, key$public))
})

test_that("Digital signatures verification - Dilithium3", {

  key <- keygen_dilithium(3)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)

  expect_true(verify_dilithium(important_message, signature, key$public))

  expect_false(verify_dilithium("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != 0L) forged_signature[1] <- 0L else forged_signature[1] <- 255L
  expect_false(verify_dilithium(important_message, forged_signature, key$public))
})

test_that("Digital signatures verification - Dilithium5", {

  key <- keygen_dilithium(5)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)

  expect_true(verify_dilithium(important_message, signature, key$public))

  expect_false(verify_dilithium("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != 0L) forged_signature[1] <- 0L else forged_signature[1] <- 255L
  expect_false(verify_dilithium(important_message, forged_signature, key$public))
})

test_that("Digital signatures verification fails with bad parameters", {

  key <- keygen_dilithium(2)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)

  expect_error(verify_dilithium(important_message, "not_a_signature", key$public))  # bad signature
  expect_error(verify_dilithium(important_message, signature, key$private))  # bad key type

  small_signature <- signature[1:100]
  class(small_signature) <- "pqcrypto_signature"
  expect_error(verify_dilithium(important_message, small_signature, key$public))  # c++ error

  key <- keygen_kyber()
  expect_error(verify_dilithium(important_message, signature, key$public)) # bad key algorithm
})
