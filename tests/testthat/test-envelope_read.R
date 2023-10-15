test_that("Envelope reading works", {

  key <- keygen_kyber()
  secret_message <- "Hello world!!"
  env <- envelope_create(secret_message, key$public)
  fn <- write_envelope(env)

  retrieved_envelope <- read_envelope(fn)
  expect_identical(env, retrieved_envelope)

  expect_error(read_envelope("/not_a_valid/file"), "Invalid 'file_name'")
})
