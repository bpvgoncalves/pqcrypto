test_that("SLH-DSA signature (shake, 128, small)", {

  key <- keygen_slh_dsa(category = 128, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.26")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.26")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.26")
  expect_equal(length(sig$signer_infos$signature), 7856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.26")
  expect_equal(length(sig$signer_infos$signature), 7856)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.26")
    expect_equal(length(sig$signer_infos$signature), 7856)
  })
})

test_that("SLH-DSA signature (shake, 128, fast)", {

  key <- keygen_slh_dsa(category = 128, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.27")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.27")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.27")
  expect_equal(length(sig$signer_infos$signature), 17088)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.27")
  expect_equal(length(sig$signer_infos$signature), 17088)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.27")
    expect_equal(length(sig$signer_infos$signature), 17088)
  })
})

test_that("SLH-DSA signature (shake, 192, small)", {

  key <- keygen_slh_dsa(category = 192, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.28")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.28")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.28")
  expect_equal(length(sig$signer_infos$signature), 16224)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.28")
  expect_equal(length(sig$signer_infos$signature), 16224)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.28")
    expect_equal(length(sig$signer_infos$signature), 16224)
  })
})

test_that("SLH-DSA signature (shake, 192, fast)", {

  key <- keygen_slh_dsa(category = 192, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.29")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.29")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.29")
  expect_equal(length(sig$signer_infos$signature), 35664)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.29")
  expect_equal(length(sig$signer_infos$signature), 35664)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.29")
    expect_equal(length(sig$signer_infos$signature), 35664)
  })
})

test_that("SLH-DSA signature (shake, 256, small)", {

  key <- keygen_slh_dsa(category = 256, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.30")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.30")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.30")
  expect_equal(length(sig$signer_infos$signature), 29792)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.30")
  expect_equal(length(sig$signer_infos$signature), 29792)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.30")
    expect_equal(length(sig$signer_infos$signature), 29792)
  })
})

test_that("SLH-DSA signature (shake, 256, fast)", {

  key <- keygen_slh_dsa(category = 256, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.31")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.31")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.31")
  expect_equal(length(sig$signer_infos$signature), 49856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.31")
  expect_equal(length(sig$signer_infos$signature), 49856)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.31")
    expect_equal(length(sig$signer_infos$signature), 49856)
  })
})

test_that("SLH-DSA signature (sha2, 128, small)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 128, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.20")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.20")
  expect_equal(length(sig$signer_infos$signature), 7856)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.20")
  expect_equal(length(sig$signer_infos$signature), 7856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.20")
  expect_equal(length(sig$signer_infos$signature), 7856)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.20")
    expect_equal(length(sig$signer_infos$signature), 7856)
  })
})

test_that("SLH-DSA signature (sha2, 128, fast)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 128, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.21")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.21")
  expect_equal(length(sig$signer_infos$signature), 17088)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.21")
  expect_equal(length(sig$signer_infos$signature), 17088)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.21")
  expect_equal(length(sig$signer_infos$signature), 17088)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.21")
    expect_equal(length(sig$signer_infos$signature), 17088)
  })
})

test_that("SLH-DSA signature (sha2, 192, small)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 192, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.22")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.22")
  expect_equal(length(sig$signer_infos$signature), 16224)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.22")
  expect_equal(length(sig$signer_infos$signature), 16224)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.22")
  expect_equal(length(sig$signer_infos$signature), 16224)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.22")
    expect_equal(length(sig$signer_infos$signature), 16224)
  })
})

test_that("SLH-DSA signature (sha2, 192, fast)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 192, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.23")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.23")
  expect_equal(length(sig$signer_infos$signature), 35664)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.23")
  expect_equal(length(sig$signer_infos$signature), 35664)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.23")
  expect_equal(length(sig$signer_infos$signature), 35664)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.23")
    expect_equal(length(sig$signer_infos$signature), 35664)
  })
})

test_that("SLH-DSA signature (sha2, 256, small)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 256, type = "small")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.24")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.24")
  expect_equal(length(sig$signer_infos$signature), 29792)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.24")
  expect_equal(length(sig$signer_infos$signature), 29792)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.24")
  expect_equal(length(sig$signer_infos$signature), 29792)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.24")
    expect_equal(length(sig$signer_infos$signature), 29792)
  })
})

test_that("SLH-DSA signature (sha2, 256, fast)", {

  key <- keygen_slh_dsa(hash_type = "sha2", category = 256, type = "fast")
  sig <- sign_slh_dsa(key$private, "Hello world!!")
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.25")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_slh_dsa(key$private, 1234567890)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.25")
  expect_equal(length(sig$signer_infos$signature), 49856)

  sig <- sign_slh_dsa(key$private, TRUE)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.25")
  expect_equal(length(sig$signer_infos$signature), 49856)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  sig <- sign_slh_dsa(key$private, obj)
  expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
  expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.25")
  expect_equal(length(sig$signer_infos$signature), 49856)

  httptest2::without_internet({
    sig <- sign_slh_dsa(key$private, "Hello world!!")
    expect_true(inherits(sig, "pqcrypto_cms_id_signed_data"))
    expect_equal(sig$signer_infos$signature_algorithm, "2.16.840.1.101.3.4.3.25")
    expect_equal(length(sig$signer_infos$signature), 49856)
  })
})

test_that("SLH-DSA digital signature fails on wrong parameters", {

  key <- keygen_slh_dsa()
  expect_error(sign_slh_dsa("not_a_key", "text_message")) # wrong key object
  expect_error(sign_slh_dsa(key$public, "text_message"))  # wrong key

  key <- keygen_ml_kem()
  expect_error(sign_slh_dsa(key$private, "text_message")) # wrong key algorithm

  key <- keygen_ml_dsa()
  expect_error(sign_slh_dsa(key$private, "text_message")) # wrong key algorithm

  small_key <- key$private[1:25]
  class(small_key) <- "pqcrypto_private_key"
  attr(small_key, "algorithm") <- "2.16.840.1.101.3.4.3.25"
  expect_error(sign_slh_dsa(small_key, "text_message"))   # wrong key size
})
