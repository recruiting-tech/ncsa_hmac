defmodule NcsaHmac.PlugConnSignerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias NcsaHmac.PlugConnSigner
  # doctest NcsaHmac

  # Crypto Implementation Note:
  # For all computed hashes the ruby OpenSSL gem was used.
  # Cryptographic hashes are expected to be the same given the same inputs
  # regarless of the language that implements the hash function.
  # Further validation against other crypto libraries would be nice,
  # though it should not produce different results.

  @key_id "SECRET_KEY_ID"
  @signing_key "abcdefghijkl"
  @target_md5_hash "ecadfcaf838cc3166d637a196530bd90"
  @target_body %{"abc" => "def"}
  @expected_sha512_signature "svO1jOUW+3wSVc/rzs4WQSOsWtABji6ppN0AkS++2SNvt6fPPvxonLV5WRgFaqnVc63RNmAndel8e/hxoNB4Pg=="
  @signature_params %{
    "key_id"=>@key_id,
    "key_secret"=>@signing_key,
    "path" => "/api/auth",
    "method" => "POST",
    "params" => @target_body,
    "date" => "Fri, 22 Jul 2016",
    "content-type" => "application/json"
  }

  test "do not set content-digest if the body is empty" do
    conn = conn(:put, "/api/auth", "")
    signed_conn =  PlugConnSigner.sign!(conn, @key_id, @signing_key)
    assert Plug.Conn.get_req_header(signed_conn, "content-digest") == [""]
  end

  test "do not set content-digest if the body is empty map" do
    conn = conn(:put, "/api/auth", %{})
    signed_conn =  PlugConnSigner.sign!(conn, @key_id, @signing_key)
    assert Plug.Conn.get_req_header(signed_conn, "content-digest") == [""]
  end

  test "calculate a MD5 digest of the message body/params" do
    conn = conn(:put, "/api/auth", @target_body)
    signed_conn =  PlugConnSigner.sign!(conn, @key_id, @signing_key)
    assert Plug.Conn.get_req_header(signed_conn, "content-digest") == [@target_md5_hash]
  end

  test "MD5 digest calculations and json encoding match" do
    req_map = %{"abc" => 123, "def" => 456}
    conn = conn(:put, "/api/auth", req_map)
    md5_hash = Base.encode16(:erlang.md5("{\"abc\":123,\"def\":456}"), case: :lower)
    signed_conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)
    signature = Plug.Conn.get_req_header(signed_conn, "content-digest")

    assert signature == [md5_hash]
  end

  test "calculate the MD5 hash from the map values only" do
    req_map = %{"abc" => 123, "def" => 456, 123 => 789}
    conn = conn(:post, "/api/auth", req_map)
    md5_hash = Base.encode16(:erlang.md5("{\"123\":789,\"abc\":123,\"def\":456}"), case: :lower)
    signed_conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)
    signature = Plug.Conn.get_req_header(signed_conn, "content-digest")
    assert signature == [md5_hash]
  end

  test "calculate the MD5 hash from the map with string and integer values AND sort the keys alphabetically" do
    req_map = %{"def" => "ghi", "abc" => 123, 123 => "789"}
    conn = conn(:put, "/api/auth", req_map)
    md5_hash = Base.encode16(:erlang.md5("{\"123\":\"789\",\"abc\":123,\"def\":\"ghi\"}"), case: :lower)
    signed_conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)
    signature = Plug.Conn.get_req_header(signed_conn, "content-digest")
    assert signature == [md5_hash]
  end

  test "calculate the MD5 hash from the map values with a nested list AND sort the keys alphabetically" do
    req_map = %{"def" => 456, "abc" => 123, 123 => [1,2,3]}
    conn = conn(:post, "/api/auth", req_map)
    md5_hash = Base.encode16(:erlang.md5("{\"123\":[1,2,3],\"abc\":123,\"def\":456}"), case: :lower)
    signed_conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)
    signature = Plug.Conn.get_req_header(signed_conn, "content-digest")
    assert signature == [md5_hash]
  end

  test "set the date when none is passed in the request" do
    {:ok, iso_date} = Timex.Format.DateTime.Formatter.format(Timex.now, "{ISOdate}" )
    conn = conn(:get, "/api/auth", @target_body)
    assert Plug.Conn.get_req_header(conn, "date") == []
    signed_conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)
    assert String.match?(List.first(Plug.Conn.get_req_header(signed_conn, "date")), ~r/#{iso_date}/)
  end

  test "canonical message content" do
    conn = conn(:head, "/api/auth", @target_body)
    date = "1234"
    conn = Plug.Conn.put_req_header(conn, "date", date)
    canonical = PlugConnSigner.canonicalize_conn(conn)
    assert canonical == "HEAD" <> "\n"
      <> "multipart/mixed; boundary=plug_conn_test" <> "\n"
      <> @target_md5_hash <> "\n"
      <> date <> "\n"
      <> "/api/auth"
  end

  test "GET canonical message content with query_string ignores the request body and query string" do
    conn = conn(:get, "/api/auth?queryString=something", @target_body)
    date = "1234"
    conn = Plug.Conn.put_req_header(conn, "date", date)
    |> Plug.Conn.put_req_header("content-type", "application/json")
    canonical = PlugConnSigner.canonicalize_conn(conn)
    assert canonical == "GET" <> "\n"
      <> "application/json" <> "\n"
      <> "\n"
      <> date <> "\n"
      <> "/api/auth"
  end

  test "computed signature matches a known SHA512 signature" do
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    signature = PlugConnSigner.signature(conn, @signing_key)
    assert signature == @expected_sha512_signature
  end

  test "computed signature matches a known SHA384 signature" do
    expected_sha384_signature = "LkXSygPRNKTuqHxUEzM6iUxLnTW4I4D+G7JxVDHKj1l/7qeb/i9rp8aX+b7eW0YN"
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    signature = PlugConnSigner.signature(conn, @signing_key, :sha384)
    assert signature == expected_sha384_signature
  end

  test "computed signature matches a known SHA256 signature" do
    expected_sha256_signature = "FzfelqPkbfyA2WK/ANhBB4vlqdXQ5m1h53fELgN5QB4="
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    signature = PlugConnSigner.signature(conn, @signing_key, :sha256)
    assert signature == expected_sha256_signature
  end

  test "GET request signature matches a known SHA384 signature ignoring the body and the query string" do
    expected_sha384_signature = "LabF5wrjPKo4BzXYONqYFJWxOzDwac7/PyRLwteWNbEfYBnBAq5cCAXmxKIJHV/A"
    conn = conn(:get, "/api/auth?queryString=something", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    signature = PlugConnSigner.signature(conn, @signing_key, :sha384)
    assert signature == expected_sha384_signature
  end

  test "computed signature matches when content_type == '' " do
    expected_signature = "u8+hRiEYpt+cDoOdx0Lt6Ymmw2bc3iA02l3rVEg9en3WPWEAS1yG9It94ds3/bkQmexnS+dNsQ3km8Ewc5Jj7w=="
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", "")
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    signature = PlugConnSigner.signature(conn, @signing_key)
    assert signature == expected_signature
  end

  test "computed signature matches when content_type is not explicitly set " do
    expected_signature = "b0epQjAD/E2yjG9FXN8K2dtRbtSds1Re3eJB3CHt+JajoSZC6mExbiE85Oj9v2yNRURE3uIIo0ltVh0hOZZ7dQ=="
    default_content_type = "multipart/mixed; boundary=plug_conn_test"
    conn = conn(:post, "/api/auth", @target_body)
    assert Plug.Conn.get_req_header(conn, "content-type") == [default_content_type]
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])

    signature = PlugConnSigner.signature(conn, @signing_key)
    assert signature == expected_signature
  end

  test "sign the authorization header in the request" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)

    signature = List.first(Plug.Conn.get_req_header(conn, "authorization"))
    assert signature == auth_string
  end

  test "Missing key_id throws an exception" do
    conn = conn(:post, "/api/auth", @target_body)
    assert_raise(NcsaHmac.SigningError, fn ->
        PlugConnSigner.authorization(conn, nil, @signing_key)
      end
    )
    assert_raise(NcsaHmac.SigningError, fn ->
        PlugConnSigner.authorization(conn, "", @signing_key)
      end
    )
  end

  test "Missing key_secret throws an exception" do
    conn = conn(:post, "/api/auth", @target_body)
    assert_raise(NcsaHmac.SigningError, fn ->
        PlugConnSigner.authorization(conn, @key_id, nil)
      end
    )
    assert_raise(NcsaHmac.SigningError, fn ->
        PlugConnSigner.authorization(conn, @key_id, "")
      end
    )
  end

  test "handle Plug wrapping the params in _json key" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", %{"_json" => @target_body})
    conn = Plug.Conn.put_req_header(conn, "content-type", @signature_params["content-type"])
    conn = Plug.Conn.put_req_header(conn, "date", @signature_params["date"])
    conn = PlugConnSigner.sign!(conn, @key_id, @signing_key)

    signature = List.first(Plug.Conn.get_req_header(conn, "authorization"))
    assert signature == auth_string
  end
end
