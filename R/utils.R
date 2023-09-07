
msg_to_raw <- function(msg) {
  serialize(msg, NULL)
}

msg_to_integer <- function(msg) {
  as.integer(msg_to_raw(msg))
}
