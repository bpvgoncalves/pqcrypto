test_that("Sphincs+ signature (shake, 128, small)", {

  key <- keygen_sphincs(category = 128, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 7856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 7856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 7856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 7856)
})

test_that("Sphincs+ signature (shake, 128, fast)", {

  key <- keygen_sphincs(category = 128, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 17088)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 17088)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 17088)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 17088)
})

test_that("Sphincs+ signature (shake, 192, small)", {

  key <- keygen_sphincs(category = 192, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 16224)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 16224)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 16224)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 16224)
})

test_that("Sphincs+ signature (shake, 192, fast)", {

  key <- keygen_sphincs(category = 192, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 35664)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 35664)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 35664)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 35664)
})

test_that("Sphincs+ signature (shake, 256, small)", {

  key <- keygen_sphincs(category = 256, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 29792)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 29792)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 29792)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 29792)
})

test_that("Sphincs+ signature (shake, 256, small)", {

  key <- keygen_sphincs(category = 256, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 49856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 49856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 49856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_signature"))
  expect_equal(attr(sig, "algorithm"), "sphincs+")
  expect_equal(length(sig), 49856)
})

test_that("Sphincs+ digital signature fails on wrong parameters", {

  key <- keygen_sphincs()
  expect_error(sign_sphincs("not_a_key", "text_message")) # wrong key object
  expect_error(sign_sphincs(key$public, "text_message"))  # wrong key

  key <- keygen_kyber()
  expect_error(sign_sphincs(key$private, "text_message")) # wrong key algorithm

  key <- keygen_dilithium()
  expect_error(sign_sphincs(key$private, "text_message")) # wrong key algorithm

  small_key <- key$private[1:25]
  class(small_key) <- "pqcrypto_private_key"
  attr(small_key, "algorithm") <- "sphincs+"
  expect_error(sign_sphincs(small_key, "text_message"))   # wrong key size
})
