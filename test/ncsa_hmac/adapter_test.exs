defmodule NcsaHmac.AdapterTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias NcsaHmac.Adapter
  # doctest NcsaHmac

  # Crypto Implementation Note:
  # For all computed hashes the ruby OpenSSL gem was used.
  # Cryptographic hashes are expected to be the same given the same inputs
  # regarless of the language that implements the hash function.
  # Further validation against other crypto libraries would be nice,
  # though it should not produce different results.

  @key_id "SECRET_KEY_ID"
  @key_secret "abcdefghijkl"
  @target_md5_hash "ecadfcaf838cc3166d637a196530bd90"
  @target_body %{"abc" => "def"}
  @path "/api/auth"
  @date "Fri, 22 Jul 2016"
  @opts [key_id: @key_id, key_secret: @key_secret]

  setup do
    bypass = Bypass.open()
    {:ok, bypass: bypass}
  end

  describe "get/3" do
    test "GET canonical message content with query_string ignores the request body and query string", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["content-type"] == "application/json"
        refute headers["date"] == nil
        refute headers["authorization"] == nil
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.get(url, @opts)
    end

    test "GET doesn't override the date value when headers is a map", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["content-type"] == "application/json"
        assert headers["date"] == @date
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.get(url, %{"date" => @date}, @opts)
    end

    test "GET with query_string ignores the query string", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["content-type"] == "application/json"
        assert headers["date"] == @date
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path <> "?queryString=something"
      Adapter.get(url, %{"date" => @date}, @opts)
    end

    test "GET request signature matches a known SHA256 signature ignoring the body and the query string", %{bypass: bypass} do
      expected_sha256_signature = "NCSA.HMAC SECRET_KEY_ID:hWOLlddrw5w06aft8R/nnOt2v/VYNPCFlta3Vz0DuBI="

      Bypass.expect(bypass, fn conn ->
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["authorization"] == expected_sha256_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path <> "?queryString=something"
      opts = Keyword.put(@opts, :hash_type, :sha256)
      Adapter.get(url, %{"date" => @date}, opts)
    end

    test "GET request signature matches a known SHA384 signature ignoring the body and the query string", %{bypass: bypass} do
      expected_sha384_signature = "NCSA.HMAC SECRET_KEY_ID:LabF5wrjPKo4BzXYONqYFJWxOzDwac7/PyRLwteWNbEfYBnBAq5cCAXmxKIJHV/A"
      Bypass.expect(bypass, fn conn ->
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["authorization"] == expected_sha384_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path <> "?queryString=something"
      opts = Keyword.put(@opts, :hash_type, :sha384)
      Adapter.get(url, %{"date" => @date}, opts)
    end

    test "GET request signature matches a known SHA512 signature ignoring the body and the query string", %{bypass: bypass} do
      expected_sha512_signature = "NCSA.HMAC SECRET_KEY_ID:6zMj3bvxSlvIS6/HPxtbQuJtfOWE7acS3mxwhg4phVe7enFpdVp8nnHassX13/yw2Sh7U7mOV1A+ILIepunOpQ=="
      Bypass.expect(bypass, fn conn ->
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["authorization"] == expected_sha512_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.get(url, %{"date" => @date}, @opts)
    end
  end

  describe "head/3" do
    test "HEAD request signature matches a known SHA256 signature", %{bypass: bypass} do
      expected_sha256_signature = "NCSA.HMAC SECRET_KEY_ID:uhihJFQJueLBIJ9wdphkOQ/31Hkvm0D+SG6k8EyOhw0="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == ""
        assert headers["authorization"] == expected_sha256_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha256)
      Adapter.head(url, %{"date" => @date}, opts)
    end
  end

  describe "options/3" do
    test "OPTIONS request signature matches a known SHA384 signature", %{bypass: bypass} do
      expected_sha384_signature = "NCSA.HMAC SECRET_KEY_ID:0tMedxfNxdpDothcTlX+GjItrOjgBkdSl7TxXbxbck7j9GfU1QSDYIZrj5Yi2GNF"

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == ""
        assert headers["authorization"] == expected_sha384_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha384)
      Adapter.options(url, %{"date" => @date}, opts)
    end
  end

  describe "post/4" do
    test "POST canonical message content", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["content-type"] == "application/json"
        refute headers["date"] == nil
        refute headers["authorization"] == nil
        assert headers["content-digest"] == @target_md5_hash
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.post(url, @target_body, @opts)
    end

    test "POST request signature matches a known SHA256 signature", %{bypass: bypass} do
       expected_sha256_signature = "NCSA.HMAC SECRET_KEY_ID:4hL6GNR2MJlg5HFwnAfBSqeUFkLEcJ4WXcDwsY8KC9k="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == "1dd1149885bda19aa65a942756249273"
        assert headers["authorization"] == expected_sha256_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha256)
      Adapter.post(url, %{abc: "def", def: "ghi"}, %{"date" => @date}, opts)
    end

    test "POST request signature matches a known SHA384 signature", %{bypass: bypass} do
       expected_sha384_signature = "NCSA.HMAC SECRET_KEY_ID:cPW+DIINnMK8tI4/ExtuZLf5+InwvH6wekVq435daMpkqeORBU4gbNty6bNRXira"

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == "1dd1149885bda19aa65a942756249273"
        assert headers["authorization"] == expected_sha384_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha384)
      Adapter.post(url, %{abc: "def", def: "ghi"}, %{"date" => @date}, opts)
    end

    test "POST request signature matches a known SHA512 signature", %{bypass: bypass} do
       expected_sha512_signature = "NCSA.HMAC SECRET_KEY_ID:Wt0ITtZqAfSCBTyKxOs7B5X8fp3Yi6x2LSKQi5g/Z59CsVqWkuNk/2jlz7slmR2UovaZydjLPp9dSnCXhwk+fg=="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == "1dd1149885bda19aa65a942756249273"
        assert headers["authorization"] == expected_sha512_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha512)
      Adapter.post(url, %{abc: "def", def: "ghi"}, %{"date" => @date}, opts)
    end
  end

  describe "put/4" do
    test "PUT request signature matches a known SHA512 signature", %{bypass: bypass} do
      expected_sha512_signature = "NCSA.HMAC SECRET_KEY_ID:wIGMGASTOyd5BWvpao7KnxRUto1dI1mijIpvkvM0rAaf5OCCOkS+r4eyVzFzQcxTBBphs5mfGRZIFMOW3dPVeg=="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == "1dd1149885bda19aa65a942756249273"
        assert headers["authorization"] == expected_sha512_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha512)
      Adapter.put(url, %{abc: "def", def: "ghi"}, %{"date" => @date}, opts)
    end

    test "do not set content-digest if the body is nil", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        refute headers["date"] == nil
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.put(url, nil, @opts)
    end

    test "do not set content-digest if the body is empty string", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        refute headers["date"] == nil
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.put(url, "", @opts)
    end

    test "do not set content-digest if the body is empty map", %{bypass: bypass} do
      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        refute headers["date"] == nil
        assert headers["content-digest"] == ""
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      Adapter.put(url, %{}, @opts)
    end
  end

  describe "patch/4" do
    test "PATCH request signature matches a known SHA512 signature", %{bypass: bypass} do
      expected_sha512_signature = "NCSA.HMAC SECRET_KEY_ID:7cMdHZavAjmJprGeUnr+Lj4I6aFM6VX+v+ft44THYATMIwQu7m6uEJdVJ/Er2mCue0z4Nyt6Z7PNRjWhL1xf2w=="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == "1dd1149885bda19aa65a942756249273"
        assert headers["authorization"] == expected_sha512_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha512)
      Adapter.patch(url, %{abc: "def", def: "ghi"}, %{"date" => @date}, opts)
    end
  end

  describe "delete/4" do
    test "DELETE request signature matches a known SHA256 signature", %{bypass: bypass} do
      expected_sha256_signature = "NCSA.HMAC SECRET_KEY_ID:4kmnDhzQ+Tp/c7zsTGfRhBnDXR+Zrks37ijx/ZR9KEs="

      Bypass.expect(bypass, fn conn ->
        assert conn.request_path == "/api/auth"
        headers = conn.req_headers |> Enum.into(%{})
        assert headers["date"] == @date
        assert headers["content-digest"] == ""
        assert headers["authorization"] == expected_sha256_signature
        Plug.Conn.resp(conn, 200, "ok")
      end)
      url = "http://localhost:#{bypass.port}" <> @path
      opts = Keyword.put(@opts, :hash_type, :sha256)
      Adapter.delete(url, %{"date" => @date}, opts)
    end
  end

  test "calculate the MD5 hash from the map values with a nested list AND sort the keys alphabetically", %{bypass: bypass} do
    md5_hash = Base.encode16(:erlang.md5("{123:[1,2,3],\"abc\":123,\"def\":456}"), case: :lower)
    Bypass.expect(bypass, fn conn ->
      assert conn.request_path == "/api/auth"
      headers = conn.req_headers |> Enum.into(%{})
      assert headers["content-digest"] == md5_hash
      refute headers["authorization"] == nil
      Plug.Conn.resp(conn, 200, "ok")
    end)

    req_map = %{"def" => 456, "abc" => 123, 123 => [1,2,3]}
    url = "http://localhost:#{bypass.port}" <> @path
    Adapter.patch(url, req_map, @opts)
  end

  test "Missing key_id throws an exception", %{bypass: bypass} do
    url = "http://localhost:#{bypass.port}" <> @path

    assert_raise(NcsaHmac.SigningError, fn ->
      opts = [key_id: "", key_secret: @key_secret]
      Adapter.get(url, opts)
    end)
    assert_raise(NcsaHmac.SigningError, fn ->
      opts = [key_id: nil, key_secret: @key_secret]
      Adapter.get(url, opts)
    end)
  end

  test "Missing key_secret throws an exception", %{bypass: bypass} do
    url = "http://localhost:#{bypass.port}" <> @path

    assert_raise(NcsaHmac.SigningError, fn ->
      opts = [key_id: @key_id, key_secret: ""]
      Adapter.get(url, opts)
    end)
    assert_raise(NcsaHmac.SigningError, fn ->
      opts = [key_id: @key_id, key_secret: nil]
      Adapter.get(url, opts)
    end)
  end
end
