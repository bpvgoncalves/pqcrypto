test_that("Digital signatures verification - ML-DSA-44", {

  key <- keygen_ml_dsa(2)
  important_message <- "Hello world!!"
  signature <- sign_ml_dsa(key$private, important_message)

  expect_true(verify_ml_dsa(important_message, signature, key$public))

  expect_false(verify_ml_dsa("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature$signer_infos$signature[1] != as.raw(0L)) {
    forged_signature$signer_infos$signature[1] <- as.raw(0L)
  } else {
    forged_signature$signer_infos$signature[1] <- as.raw(255L)
  }
  expect_false(verify_ml_dsa(important_message, forged_signature, key$public))

  forged_signature <- signature
  forged_signature$encap_content_info <- as.cms_data("Forged Message")
  expect_false(verify_ml_dsa("Forged Message", forged_signature, key$public))

})

test_that("Digital signatures verification - ML-DSA-65", {

  key <- keygen_ml_dsa(3)
  important_message <- "Hello world!!"
  signature <- sign_ml_dsa(key$private, important_message)

  expect_true(verify_ml_dsa(important_message, signature, key$public))

  expect_false(verify_ml_dsa("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature$signer_infos$signature[1] != as.raw(0L)) {
    forged_signature$signer_infos$signature[1] <- as.raw(0L)
  } else {
    forged_signature$signer_infos$signature[1] <- as.raw(255L)
  }
  expect_false(verify_ml_dsa(important_message, forged_signature, key$public))

  forged_signature <- signature
  forged_signature$encap_content_info <- as.cms_data("Forged Message")
  expect_false(verify_ml_dsa("Forged Message", forged_signature, key$public))
})

test_that("Digital signatures verification - ML-DSA-87", {

  key <- keygen_ml_dsa(5)
  important_message <- "Hello world!!"
  signature <- sign_ml_dsa(key$private, important_message)

  expect_true(verify_ml_dsa(important_message, signature, key$public))

  expect_false(verify_ml_dsa("tampered_message", signature, key$public))

  forged_signature <- signature
  if (forged_signature$signer_infos$signature[1] != as.raw(0L)) {
    forged_signature$signer_infos$signature[1] <- as.raw(0L)
  } else {
    forged_signature$signer_infos$signature[1] <- as.raw(255L)
  }
  expect_false(verify_ml_dsa(important_message, forged_signature, key$public))

  forged_signature <- signature
  forged_signature$encap_content_info <- as.cms_data("Forged Message")
  expect_false(verify_ml_dsa("Forged Message", forged_signature, key$public))
})

test_that("Digital signatures verification fails with bad parameters", {

  key <- keygen_ml_dsa(2)
  important_message <- "Hello world!!"
  signature <- sign_ml_dsa(key$private, important_message)

  expect_error(verify_ml_dsa(important_message, "not_a_signature", key$public))  # bad signature
  expect_error(verify_ml_dsa(important_message, signature, key$private))  # bad key type

  small_signature <- signature
  small_signature$signer_infos$signature <- small_signature$signer_infos$signature[1:100]
  expect_error(verify_ml_dsa(important_message, small_signature, key$public))  # c++ error

  key <- keygen_ml_kem()
  expect_error(verify_ml_dsa(important_message, signature, key$public)) # bad key algorithm

  key <- keygen_sphincs()
  expect_error(verify_ml_dsa(important_message, signature, key$public)) # bad key algorithm

  key <- keygen_ml_dsa()
  expect_error(verify_ml_dsa(important_message, signature, key$public)) # mismatching key
})
