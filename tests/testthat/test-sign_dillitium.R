test_that("Dilithium2 digital signature", {
  withr::local_options(lifecycle_verbosity = "quiet")
  key <- keygen_dilithium(2)

  sig <- sign_dilithium(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.1")
  expect_equal(length(sig$signer_infos$signature), 2420)

  sig <- sign_dilithium(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.1")
  expect_equal(length(sig$signer_infos$signature), 2420)

  sig <- sign_dilithium(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.1")
  expect_equal(length(sig$signer_infos$signature), 2420)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_dilithium(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.1")
  expect_equal(length(sig$signer_infos$signature), 2420)

  httptest2::without_internet({
    sig <- sign_dilithium(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.1")
    expect_equal(length(sig$signer_infos$signature), 2420)
  })
})

test_that("Dilithium3 digital signature", {
  withr::local_options(lifecycle_verbosity = "quiet")
  key <- keygen_dilithium(3)

  sig <- sign_dilithium(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.2")
  expect_equal(length(sig$signer_infos$signature), 3309)

  sig <- sign_dilithium(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.2")
  expect_equal(length(sig$signer_infos$signature), 3309)

  sig <- sign_dilithium(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.2")
  expect_equal(length(sig$signer_infos$signature), 3309)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_dilithium(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.2")
  expect_equal(length(sig$signer_infos$signature), 3309)

  httptest2::without_internet({
    sig <- sign_dilithium(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.2")
    expect_equal(length(sig$signer_infos$signature), 3309)
  })
})

test_that("Dilithium5 digital signature", {
  withr::local_options(lifecycle_verbosity = "quiet")
  key <- keygen_dilithium(5)

  sig <- sign_dilithium(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.3")
  expect_equal(length(sig$signer_infos$signature), 4627)

  sig <- sign_dilithium(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.3")
  expect_equal(length(sig$signer_infos$signature), 4627)

  sig <- sign_dilithium(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.3")
  expect_equal(length(sig$signer_infos$signature), 4627)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_dilithium(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.3")
  expect_equal(length(sig$signer_infos$signature), 4627)

  httptest2::without_internet({
    sig <- sign_dilithium(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.2.3")
    expect_equal(length(sig$signer_infos$signature), 4627)
  })
})


test_that("Dilithium digital signature fails on wrong parameters", {
  withr::local_options(lifecycle_verbosity = "quiet")
  key <- keygen_dilithium()
  expect_error(sign_dilithium("not_a_key", "text_message")) # wrong key object
  expect_error(sign_dilithium(key$public, "text_message"))  # wrong key

  key <- keygen_ml_kem()
  expect_error(sign_dilithium(key$private, "text_message")) # wrong key algorithm

  small_key <- key$private[1:25]
  class(small_key) <- "pqcrypto_private_key"
  attr(small_key, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.1.2.1"
  expect_error(sign_dilithium(small_key, "text_message"))   # c++ error
})
