test_that("Write Kyber key-pair", {

  key <- keygen_kyber()
  path <- tempdir()

  write_key(key, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key$private, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$private, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$public, path)
  expect_false(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair.pub"))

  expect_error(write_key("not_a_key", path))
  expect_error(write_key(key, "not_a_path"))
})

test_that("Write Dilithium key-pair", {

  key <- keygen_dilithium()
  path <- tempdir()

  write_key(key, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key$private, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$private, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$public, path)
  expect_false(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair.pub"))

  expect_error(write_key("not_a_key", path))
  expect_error(write_key(key, "not_a_path"))
})

test_that("Write Sphincs+ key-pair", {

  key <- keygen_kyber()
  path <- tempdir()

  write_key(key, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair"))
  unlink(paste0(path, "/keypair.pub"))

  write_key(key$private, path)
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$private, path, "mypass")
  expect_true(file.exists(paste0(path, "/keypair")))
  expect_false(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair"), n = 1), "-----BEGIN ENCRYPTED PRIVATE KEY-----")
  unlink(paste0(path, "/keypair"))

  write_key(key$public, path)
  expect_false(file.exists(paste0(path, "/keypair")))
  expect_true(file.exists(paste0(path, "/keypair.pub")))
  expect_equal(readLines(paste0(path, "/keypair.pub"), n = 1), "-----BEGIN PUBLIC KEY-----")
  unlink(paste0(path, "/keypair.pub"))

  expect_error(write_key("not_a_key", path))
  expect_error(write_key(key, "not_a_path"))
})

test_that("Display sample key", {

  key <- readRDS(test_path("testdata", "key"))

  expect_snapshot({
    write_key(key, NULL)
    write_key(key$private, NULL)
    write_key(key$public, NULL)
  })

})
