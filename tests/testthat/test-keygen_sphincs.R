test_that("Sphincs+ keys generation (shake, 128, small)", {

  k <- keygen_sphincs(category = 128, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 64)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 32)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.2")
})

test_that("Sphincs+ keys generation (shake, 128, fast)", {

  k <- keygen_sphincs(category = 128, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 64)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 32)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.4")
})

test_that("Sphincs+ keys generation (shake, 192, small)", {

  k <- keygen_sphincs(category = 192, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 96)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 48)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.6")
})

test_that("Sphincs+ keys generation (shake, 192, fast)", {

  k <- keygen_sphincs(category = 192, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 96)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 48)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
})

test_that("Sphincs+ keys generation (default, default, default)", {

  k <- keygen_sphincs()
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 96)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 48)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.8")
})

test_that("Sphincs+ keys generation (shake, 256, small)", {

  k <- keygen_sphincs(category = 256, type = "small")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 128)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 64)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.10")
})

test_that("Sphincs+ keys generation (shake, 256, fast)", {

  k <- keygen_sphincs(category = 256, type = "fast")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 128)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 64)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.12")
})

test_that("Sphincs+ keys generation (sha2, 128, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 128, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 64)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 32)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.1")
})

test_that("Sphincs+ keys generation (sha2, 128, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 128, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 64)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 32)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.3")
})

test_that("Sphincs+ keys generation (sha2, 192, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 192, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 96)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 48)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.5")
})

test_that("Sphincs+ keys generation (sha2, 192, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 192, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 96)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 48)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.7")
})

test_that("Sphincs+ keys generation (sha2, 256, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 256, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 128)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 64)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.9")
})

test_that("Sphincs+ keys generation (sha2, 256, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 256, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private$key), 128)
  expect_equal(k$private$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public$key), 64)
  expect_equal(k$public$algorithm, "1.3.6.1.4.1.54392.5.1859.1.3.11")
})

test_that("Keys generation fails on wrong parameters", {

  expect_error(keygen_sphincs(1, 128, "small"))
  expect_error(keygen_sphincs("1", 128, "small"))
  expect_error(keygen_sphincs(NULL, 128, "small"))
  expect_error(keygen_sphincs(NA, 128, "small"))
  expect_error(keygen_sphincs("shake", 1024, "small"))
  expect_error(keygen_sphincs("shake", "strenght", "small"))
  expect_error(keygen_sphincs("shake", NULL, "small"))
  expect_error(keygen_sphincs("shake", NA, "small"))
  expect_error(keygen_sphincs("shake", 128, 1))
  expect_error(keygen_sphincs("shake", 128, "type"))
  expect_error(keygen_sphincs("shake", 128, NULL))
  expect_error(keygen_sphincs("shake", 128, NA))
})
