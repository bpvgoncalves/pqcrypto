test_that("cli", {

  if (requireNamespace("cli", quietly = TRUE)) {

      key <- keygen_ml_kem()
      enc <- encapsulate_ml_kem(key$public)
      expect_snapshot({
        print(key)
        print(key$private)
        print(key$public)
        print(enc$shared_secret)
      })

      key <- keygen_dilithium()
      sig <- sign_dilithium(key$private, "My message")
      expect_snapshot({
        print(key)
        print(key$private)
        print(key$public)
        print(sig)
      })

      key <- keygen_sphincs()
      sig <- sign_sphincs(key$private, "My message")
      expect_snapshot({
        print(key)
        print(key$private)
        print(key$public)
        print(sig)
      })
  } else {
    skip("Skip on missing cli package")
  }

})
