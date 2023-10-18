test_that("Signature Writing works: Dilithium", {

  key <- keygen_dilithium(2)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)
  dest <- tempfile()

  fn <- write_signature(signature, dest)
  expect_equal(fn, dest)
  expect_true(file.exists(fn))

  fn <- write_signature(signature)
  expect_true(file.exists(fn))

  expect_error(write_signature("signature"),
               "'signature' parameter does not have the expected class")
  expect_error(write_signature(key),
               "'signature' parameter does not have the expected class")

  if (Sys.info()[1] == "Linux") {
    dest <- "/fake_path/file.env"
  } else if ((Sys.info()[1] == "Windows")) {
    dest <- "z:/fake_path/file.env"
  } else {
    skip("Unknown OS")
  }
  expect_error(write_signature(signature, dest), "cannot open file")
})


test_that("Signature Writing works: Sphincs+", {

  key <- keygen_sphincs()
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)
  dest <- tempfile()

  fn <- write_signature(signature, dest)
  expect_equal(fn, dest)
  expect_true(file.exists(fn))

  fn <- write_signature(signature)
  expect_true(file.exists(fn))

  expect_error(write_signature("signature"),
               "'signature' parameter does not have the expected class")
  expect_error(write_signature(key),
               "'signature' parameter does not have the expected class")

  if (Sys.info()[1] == "Linux") {
    dest <- "/fake_path/file.env"
  } else if ((Sys.info()[1] == "Windows")) {
    dest <- "z:/fake_path/file.env"
  } else {
    skip("Unknown OS")
  }
  expect_error(write_signature(signature, dest), "cannot open file")
})
