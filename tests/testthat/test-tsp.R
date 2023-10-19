
test_that("secure time stamp testing", {

  content <- as.cms_data("message")
  tsq <- as.tsp_tsq(c(content))

  # No internet connection (use system time)
  httptest2::without_internet({

    expect_message({ts = get_timestamp_secure(tsq)},
                   "Invalid or no response")

    expect_true(inherits(ts, "list"))
    expect_length(ts, 2)
    expect_true(inherits(ts[[1]], "pqcrypto_timestamp"))
    expect_null(ts[[2]])
  })

  # Force unsupported algo (http 200, PKIStatus != 0)
  tsq$message_imprint$algo <- "1.2.840.113549.1.9.4"

  expect_message({ts = get_timestamp_secure(tsq)},
                 "Time stamp not granted")

  expect_true(inherits(ts, "list"))
  expect_length(ts, 2)
  expect_true(inherits(ts[[1]], "pqcrypto_timestamp"))
  expect_null(ts[[2]])
})
