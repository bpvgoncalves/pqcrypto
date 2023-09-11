test_that("Sphincs+ signature validation (shake, 128, small)", {

  key <- keygen_sphincs(category = 128, type = "small")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})

test_that("Sphincs+ signature validation (shake, 128, fast)", {

  key <- keygen_sphincs(category = 128, type = "fast")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})

test_that("Sphincs+ signature validation (shake, 192, small)", {

  key <- keygen_sphincs(category = 192, type = "small")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})

test_that("Sphincs+ signature validation (shake, 192, fast)", {

  key <- keygen_sphincs(category = 192, type = "fast")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})

test_that("Sphincs+ signature validation (shake, 256, small)", {

  key <- keygen_sphincs(category = 256, type = "small")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})

test_that("Sphincs+ signature validation (shake, 256, fast)", {

  key <- keygen_sphincs(category = 256, type = "fast")
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)

  expect_true(verify_sphincs(important_message, signature, key$public))

  expect_false(verify_sphincs("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature[1] != as.raw(0L)) {
    forged_signature[1] <- as.raw(0L)
  } else {
    forged_signature[1] <- as.raw(255L)
  }
  expect_false(verify_sphincs(important_message, forged_signature, key$public))
})
