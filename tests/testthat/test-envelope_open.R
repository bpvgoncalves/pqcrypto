test_that("Open envelope Kyber512", {

  key <- keygen_kyber(512)

  env <- envelope_create("My very important message.", key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, "My very important message.")

  env <- envelope_create(1234567890, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, 1234567890)

  env <- envelope_create(TRUE, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, TRUE)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  env <- envelope_create(obj, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, obj)
})

test_that("Open envelope Kyber768", {

  key <- keygen_kyber(768)

  env <- envelope_create("My very important message.", key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, "My very important message.")

  env <- envelope_create(1234567890, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, 1234567890)

  env <- envelope_create(TRUE, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, TRUE)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  env <- envelope_create(obj, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, obj)
})

test_that("Open envelope Kyber1024", {

  key <- keygen_kyber(1024)

  env <- envelope_create("My very important message.", key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, "My very important message.")

  env <- envelope_create(1234567890, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, 1234567890)

  env <- envelope_create(TRUE, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, TRUE)

  obj <- data.frame(x = 1:3, y = letters[1:3])
  env <- envelope_create(obj, key$public)
  msg <- envelope_open(env, key$private)
  expect_identical(msg, obj)
})

test_that("Failure on wrong data", {

  key <- keygen_kyber(512)
  env <- envelope_create("My very important message.", key$public)

  expect_error(envelope_open(env, key$public))
  expect_error(envelope_open("not_an_envelope", key$public))

  key <- keygen_dilithium()
  expect_error(envelope_open(env, key$private))

})
