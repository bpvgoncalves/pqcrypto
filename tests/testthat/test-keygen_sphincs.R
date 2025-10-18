test_that("Sphincs+ keys generation (shake, 128, small)", {

  k <- keygen_sphincs(category = 128, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 64)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.26")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 32)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.26")
})

test_that("Sphincs+ keys generation (shake, 128, fast)", {

  k <- keygen_sphincs(category = 128, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 64)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.27")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 32)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.27")
})

test_that("Sphincs+ keys generation (shake, 192, small)", {

  k <- keygen_sphincs(category = 192, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 96)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.28")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 48)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.28")
})

test_that("Sphincs+ keys generation (shake, 192, fast)", {

  k <- keygen_sphincs(category = 192, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 96)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.29")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 48)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.29")
})

test_that("Sphincs+ keys generation (default, default, default)", {

  k <- keygen_sphincs()
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 96)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.29")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 48)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.29")
})

test_that("Sphincs+ keys generation (shake, 256, small)", {

  k <- keygen_sphincs(category = 256, type = "small")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 128)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.30")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 64)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.30")
})

test_that("Sphincs+ keys generation (shake, 256, fast)", {

  k <- keygen_sphincs(category = 256, type = "fast")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 128)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.31")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 64)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.31")
})

test_that("Sphincs+ keys generation (sha2, 128, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 128, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 64)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.20")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 32)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.20")
})

test_that("Sphincs+ keys generation (sha2, 128, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 128, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 64)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.21")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 32)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.21")
})

test_that("Sphincs+ keys generation (sha2, 192, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 192, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 96)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.22")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 48)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.22")
})

test_that("Sphincs+ keys generation (sha2, 192, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 192, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 96)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.23")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 48)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.23")
})

test_that("Sphincs+ keys generation (sha2, 256, small)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 256, type = "small")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 128)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.24")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 64)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.24")
})

test_that("Sphincs+ keys generation (sha2, 256, fast)", {

  k <- keygen_sphincs(hash_type = "sha2", category = 256, type = "fast")
  expect_s3_class(k, "pqcrypto_keypair")
  expect_s3_class(k$private, "pqcrypto_private_key")
  expect_equal(length(k$private), 128)
  expect_equal(attr(k$private, "algorithm"), "2.16.840.1.101.3.4.3.25")
  expect_s3_class(k$public, "pqcrypto_public_key")
  expect_equal(length(k$public), 64)
  expect_equal(attr(k$public, "algorithm"), "2.16.840.1.101.3.4.3.25")
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
