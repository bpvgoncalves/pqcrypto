test_that("Sphincs+ signature (shake, 128, small)", {

  key <- keygen_sphincs(category = 128, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
  expect_equal(length(sig$signer_infos$signature), 7856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
  expect_equal(length(sig$signer_infos$signature), 7856)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
    expect_equal(length(sig$signer_infos$signature), 7856)
  })
})

test_that("Sphincs+ signature (shake, 128, fast)", {

  key <- keygen_sphincs(category = 128, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
  expect_equal(length(sig$signer_infos$signature), 17088)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
  expect_equal(length(sig$signer_infos$signature), 17088)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
    expect_equal(length(sig$signer_infos$signature), 17088)
  })
})

test_that("Sphincs+ signature (shake, 192, small)", {

  key <- keygen_sphincs(category = 192, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
  expect_equal(length(sig$signer_infos$signature), 16224)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
  expect_equal(length(sig$signer_infos$signature), 16224)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
    expect_equal(length(sig$signer_infos$signature), 16224)
  })
})

test_that("Sphincs+ signature (shake, 192, fast)", {

  key <- keygen_sphincs(category = 192, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_equal(length(sig$signer_infos$signature), 35664)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_equal(length(sig$signer_infos$signature), 35664)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
    expect_equal(length(sig$signer_infos$signature), 35664)
  })
})

test_that("Sphincs+ signature (shake, 256, small)", {

  key <- keygen_sphincs(category = 256, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
  expect_equal(length(sig$signer_infos$signature), 29792)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
  expect_equal(length(sig$signer_infos$signature), 29792)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
    expect_equal(length(sig$signer_infos$signature), 29792)
  })
})

test_that("Sphincs+ signature (shake, 256, fast)", {

  key <- keygen_sphincs(category = 256, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
  expect_equal(length(sig$signer_infos$signature), 49856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
  expect_equal(length(sig$signer_infos$signature), 49856)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
    expect_equal(length(sig$signer_infos$signature), 49856)
  })
})

test_that("Sphincs+ signature (sha2, 128, small)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 128, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
  expect_equal(length(sig$signer_infos$signature), 7856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
  expect_equal(length(sig$signer_infos$signature), 7856)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
    expect_equal(length(sig$signer_infos$signature), 7856)
  })
})

test_that("Sphincs+ signature (sha2, 128, fast)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 128, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
  expect_equal(length(sig$signer_infos$signature), 17088)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
  expect_equal(length(sig$signer_infos$signature), 17088)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
    expect_equal(length(sig$signer_infos$signature), 17088)
  })
})

test_that("Sphincs+ signature (sha2, 192, small)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 192, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
  expect_equal(length(sig$signer_infos$signature), 16224)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
  expect_equal(length(sig$signer_infos$signature), 16224)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
    expect_equal(length(sig$signer_infos$signature), 16224)
  })
})

test_that("Sphincs+ signature (sha2, 192, fast)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 192, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
  expect_equal(length(sig$signer_infos$signature), 35664)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
  expect_equal(length(sig$signer_infos$signature), 35664)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
    expect_equal(length(sig$signer_infos$signature), 35664)
  })
})

test_that("Sphincs+ signature (sha2, 256, small)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 256, type = "small")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
  expect_equal(length(sig$signer_infos$signature), 29792)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
  expect_equal(length(sig$signer_infos$signature), 29792)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
    expect_equal(length(sig$signer_infos$signature), 29792)
  })
})

test_that("Sphincs+ signature (sha2, 256, fast)", {

  key <- keygen_sphincs(hash_type = "sha2", category = 256, type = "fast")
  sig <- sign_sphincs(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_sphincs(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_sphincs(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
  expect_equal(length(sig$signer_infos$signature), 49856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_sphincs(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
  expect_equal(length(sig$signer_infos$signature), 49856)

  httptest2::without_internet({
    sig <- sign_sphincs(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
    expect_equal(length(sig$signer_infos$signature), 49856)
  })
})

test_that("Sphincs+ digital signature fails on wrong parameters", {

  key <- keygen_sphincs()
  expect_error(sign_sphincs("not_a_key", "text_message")) # wrong key object
  expect_error(sign_sphincs(key$public, "text_message"))  # wrong key

  key <- keygen_ml_kem()
  expect_error(sign_sphincs(key$private, "text_message")) # wrong key algorithm

  key <- keygen_ml_dsa()
  expect_error(sign_sphincs(key$private, "text_message")) # wrong key algorithm

  small_key <- key$private[1:25]
  class(small_key) <- "pqcrypto_private_key"
  attr(small_key, "algorithm") <- "1.3.6.1.4.1.54392.5.1859.1.3.11"
  expect_error(sign_sphincs(small_key, "text_message"))   # wrong key size
})
