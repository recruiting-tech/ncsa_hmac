defmodule NcsaHmac.SigningError do
  defexception message: "Error in signing the request"
end
defmodule NcsaHmac.AuthorizationError do
  defexception message: "There was a problem verifying the HMAC signature."
end
