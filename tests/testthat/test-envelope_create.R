test_that("envelope with Kyber512", {

  key <- keygen_kyber(512)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("envelope with Kyber768", {

  key <- keygen_kyber(768)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("envelope with Kyber1024", {

  key <- keygen_kyber(1024)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("fails on bad parameters", {

  key <- keygen_kyber()
  expect_error(envelope_create("My Message.", key$private))

  key <- keygen_dilithium()
  expect_error(envelope_create("My Message.", key$public))

})
