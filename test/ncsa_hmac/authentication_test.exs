defmodule AuthKey do
  use Ecto.Schema

  schema "auth_keys" do
    field :auth_id, :string
    field :signing_key, :string
    field :slug, :string
  end
end

defmodule NcsaHmac.AuthenticationTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias NcsaHmac.Authentication

  @key_id "auth_id1"
  @signing_key "base64_signing_key"
  @target_body %{"auth_id" => "auth_id1"}
  @expected_sha512_signature "1UldRTPlTEkh1uDhVNvpB+XFgeM0OCN8uzx8+F3Xfg2QmBi02TGQI4Y58zk0AfqY20ds7NHOSWrOojORpBcG3w=="
  @date "Fri, 22 Jul 2016"
  @content_type "application/json"
  @opts [model: AuthKey, id_name: "auth_id", id_field: "auth_id", key_field: "signing_key"]

  test "#auth_id parses a valid signature and returns the auth_id" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
    |> Plug.Conn.put_req_header("authorization", auth_string)

    assert Authentication.auth_id(conn, @opts) == @key_id
  end

  test "#auth_id raises an exception when the signature cannot parse" do
    auth_string = "NCSA.HMAC " <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
    |> Plug.Conn.put_req_header("authorization", auth_string)

    assert_raise NcsaHmac.AuthorizationError, "Failed to parse authorization_signature: #{auth_string}", fn ->
      Authentication.auth_id(conn, @opts)
    end
  end

  test "#authenticate! is true for a valid signature" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:ok, true}
  end

  test "#authenticate! can get the signing_key from a user-defined field" do
    opts = [model: AuthKey, id_name: "auth_id", id_field: "auth_id", key_field: "slug"]
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", slug: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    authenticated_conn = Authentication.authenticate!(conn, opts)
    assert authenticated_conn == {:ok, true}
  end

  test "#authenticate! falls back to :signing_key by default" do
    opts = [model: AuthKey, id_name: "auth_id", id_field: "auth_id"]
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    authenticated_conn = Authentication.authenticate!(conn, opts)
    assert authenticated_conn == {:ok, true}

    # falls back to :signing_key when empty string
    opts = [model: AuthKey, id_name: "auth_id", id_field: "auth_id", key_field: ""]
    authenticated_conn = Authentication.authenticate!(conn, opts)
    assert authenticated_conn == {:ok, true}
  end

  test "can #authenticate! a valid sha384 signature" do
    sha384_signature = "qesukPOay+XazgaLEjoc7Ob0jOCmHgSqNvcg+nvcN4QZrA01SSG2P4CuP6APUBCB"
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> sha384_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
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
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
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
      |> Plug.Conn.assign(:api_key, %AuthKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:error, "Error: computed signature does not match header signature: not_a_valid_signature"}
  end

  test "#authenticate! raises AuthIdError when there is no repo assigned" do
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

  test "#authenticate! raises AuthorizationError if there is no signature" do
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @content_type)
    conn = Plug.Conn.put_req_header(conn, "date", @date)
    authenticated_conn = Authentication.authenticate!(conn, @opts)
    assert authenticated_conn == {:error, "Failed to parse authorization_signature: nil"}
  end
end
