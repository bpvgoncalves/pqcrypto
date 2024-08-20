test_that("envelope with ML-KEM-512", {

  key <- keygen_ml_kem(512)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("envelope with ML-KEM-768", {

  key <- keygen_ml_kem(768)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("envelope with ML-KEM-1024", {

  key <- keygen_ml_kem(1024)
  env <- envelope_create("Very important message.", key$public)

  expect_true(inherits(env, "pqcrypto_cms_id_enveloped_data"))
  expect_equal(length(env), 3)
})

test_that("fails on bad parameters", {

  key <- keygen_ml_kem()
  expect_error(envelope_create("My Message.", key$private))

  key <- keygen_dilithium()
  expect_error(envelope_create("My Message.", key$public))

})
