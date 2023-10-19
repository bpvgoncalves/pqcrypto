test_that("Envelope writing works", {

  key <- keygen_kyber()
  secret_message <- "Hello world!!"
  env <- envelope_create(secret_message, key$public)
  dest <- tempfile()

  fn <- write_envelope(env, dest)
  expect_equal(fn, dest)
  expect_true(file.exists(fn))

  fn <- write_envelope(env)
  expect_true(file.exists(fn))

  expect_error(write_envelope("envelope"),
               "'envelope' parameter does not have the expected class")
  expect_error(write_envelope(key),
               "'envelope' parameter does not have the expected class")

  if (Sys.info()[1] == "Linux") {
    dest <- "/fake_path/file.env"
  } else if ((Sys.info()[1] == "Windows")) {
    dest <- "z:/fake_path/file.env"
  } else {
    skip("Unknown OS")
  }
  expect_error(write_envelope(env, dest), "cannot open file")
})
