test_that("Signature Writing works: Dilithium", {

  key <- keygen_dilithium(2)
  important_message <- "Hello world!!"
  signature <- sign_dilithium(key$private, important_message)
  fn <- write_signature(signature)

  retrieved_signature <- read_signature(fn)
  expect_identical(signature, retrieved_signature)

  expect_error(read_signature("/not_a_valid/file"),
               "Invalid 'file_name'")
})

test_that("Signature Writing works: Sphincs+", {

  key <- keygen_sphincs()
  important_message <- "Hello world!!"
  signature <- sign_sphincs(key$private, important_message)
  fn <- write_signature(signature)

  retrieved_signature <- read_signature(fn)
  expect_identical(signature, retrieved_signature)

  expect_error(read_signature("/not_a_valid/file"),
               "Invalid 'file_name'")
})
