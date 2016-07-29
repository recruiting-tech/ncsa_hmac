defmodule ApiKey do
  use Ecto.Schema

  schema "api_keys" do
    field :auth_id, :string
    field :signing_key, :string
  end
end
defmodule NcsaHmac.AuthenticationTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias NcsaHmac.Authentication
  # alias PartnerAthleteSearch.ApiKey

  @key_id "auth_id1"
  @signing_key "base64_signing_key"
  @target_body %{"auth_id" => "auth_id1"}
  @expected_sha512_signature "1UldRTPlTEkh1uDhVNvpB+XFgeM0OCN8uzx8+F3Xfg2QmBi02TGQI4Y58zk0AfqY20ds7NHOSWrOojORpBcG3w=="
  @date "Fri, 22 Jul 2016"
  @content_type "application/json"
  @opts [model: ApiKey, id_name: "auth_id", id_field: "auth_id", key_name: "signing_key"]

  test "#authenticate! is true for a valid signature" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)
    authenticated_conn = Authentication.authenticate!(conn, @opts)

    assert authenticated_conn == {:ok, true}
  end

  test "can #authenticate! a valid sha384 signature" do
    sha384_signature = "qesukPOay+XazgaLEjoc7Ob0jOCmHgSqNvcg+nvcN4QZrA01SSG2P4CuP6APUBCB"
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> sha384_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)
    authenticated_conn = Authentication.authenticate!(conn, @opts)

    assert authenticated_conn == {:ok, true}
  end

  test "can #authenticate! a valid sha256 signature" do
    sha256_signature = "BOvhZJt6RMtv7AGfMvopszbdyNBNIfV2syY+m/52tO8="
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> sha256_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)
    authenticated_conn = Authentication.authenticate!(conn, @opts)

    assert authenticated_conn == {:ok, true}
  end

  test "#authenticate! fails to validate an invalid signature" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":not_a_valid_signature"

    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:error, "Error: computed signature does not match header signature: not_a_valid_signature"}
  end

  test "#authenticate! raises AuthIdError when no db record exists" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":not_a_valid_signature:something_else"

    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @content_type)
    conn = Plug.Conn.put_req_header(conn, "date", @date)
    conn = Plug.Conn.put_req_header(conn, "authorization", auth_string)
    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:error, "The signature authorization_id does not match any records. auth_id: #{@key_id}"}
  end

  test "#authenticate! raises AuthorizationError if it cannot parse the signature" do
    auth_string = "NCSA.HMAC" <> @key_id <> ":not_a_valid_signature"

    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @content_type)
    conn = Plug.Conn.put_req_header(conn, "date", @date)
    conn = Plug.Conn.put_req_header(conn, "authorization", auth_string)
    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:error, "Failed to parse authorization_signature: #{auth_string}"}
  end
end
