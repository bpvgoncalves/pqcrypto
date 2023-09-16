test_that("Read Kyber key-pair", {

  key <- keygen_kyber()
  path <- tempdir()

  write_key(key, path)
  prv <- open_key(paste0(path, "/keypair"))
  pub <- open_key(paste0(path, "/keypair.pub"))
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  prv <- open_key(paste0(path, "/keypair"), "mypass")
  pub <- open_key(paste0(path, "/keypair.pub"), "mypass")
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)

  expect_error(open_key(paste0(path, "/keypair")))
  expect_error(open_key(paste0(path, "/keypair"), "notmypass"))
  expect_error(open_key("/invalid_path/keypair", "mypass"))
  expect_error(open_key("/invalid_path/keypair.pub", "mypass"))

  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

})

test_that("Read Dilithium key-pair", {

  key <- keygen_dilithium()
  path <- tempdir()

  write_key(key, path)
  prv <- open_key(paste0(path, "/keypair"))
  pub <- open_key(paste0(path, "/keypair.pub"))
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  prv <- open_key(paste0(path, "/keypair"), "mypass")
  pub <- open_key(paste0(path, "/keypair.pub"), "mypass")
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)

  expect_error(open_key(paste0(path, "/keypair")))
  expect_error(open_key(paste0(path, "/keypair"), "notmypass"))
  expect_error(open_key("/invalid_path/keypair", "mypass"))
  expect_error(open_key("/invalid_path/keypair.pub", "mypass"))

  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

})

test_that("Read Sphincs+ key-pair", {

  key <- keygen_sphincs()
  path <- tempdir()

  write_key(key, path)
  prv <- open_key(paste0(path, "/keypair"))
  pub <- open_key(paste0(path, "/keypair.pub"))
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  prv <- open_key(paste0(path, "/keypair"), "mypass")
  pub <- open_key(paste0(path, "/keypair.pub"), "mypass")
  expect_identical(key$private, prv)
  expect_identical(key$public, pub)

  expect_error(open_key(paste0(path, "/keypair")))
  expect_error(open_key(paste0(path, "/keypair"), "notmypass"))
  expect_error(open_key("/invalid_path/keypair", "mypass"))
  expect_error(open_key("/invalid_path/keypair.pub", "mypass"))

  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

})
