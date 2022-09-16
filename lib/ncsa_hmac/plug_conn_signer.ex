defmodule NcsaHmac.PlugConnSigner do
  @default_hash :sha512
  @service_name "NCSA.HMAC"

  @moduledoc """
  The Signer module provides functions for signing a conn (web request) with a cryptographic algorithm.
  """

  @doc """
  Sign the request and set header fields as needed.

  The `sign!` method performs several steps:

  Set the `Date` header field, unless it was already set.

  Calculate the MD5 Hash of the request parameters and set the `Content-Digest`
  header.

  Canonicalize the request fields. The helps ensure that only guaranteed fields
  are used to calculate the header. It also helps ensure that the same request
  signature will be calculated the same way every time.

  Required paramters:

  * `:key_id` - The database id of the record. This is also the publically
  visible and unencrypted piece of the request signature
  * `:key_secret` - The signing_key or sercret_key that is used to sign the request.
  This is the shared secret that must be known to both the requesting server
  as well as the receiveing server. The signing_key should be kept securely and
  not shared publically.

  Optional opts:

  * `:hash_type` - Specifies the cryptographic hash function to use when computing
  the signature.
  """

  def sign!(conn, key_id, key_secret, hash_type \\ @default_hash) do
    conn
      |> Plug.Conn.fetch_query_params
      |> set_header_date
      |> set_headers(key_id, key_secret, hash_type)
  end

  @doc """
  Create a canonical string from the request that will be used to computed
  the signature. GET request must be canoncalized correctly using only the base path
  and ignoring both the query string and params that Plug.Conn adds when it
  parses the query_string.
  """
  def canonicalize_conn(conn) do
    IO.puts("-------------------------")
    IO.puts("--- canonicalize_conn ---")
    IO.inspect(conn.method)
    IO.inspect(conn.request_path)
    IO.inspect(get_header_value(conn, "date"))
    IO.inspect(content_digest(conn, get_request_params(conn)))
    IO.inspect(get_header_value(conn, "content-type"))
    IO.inspect(NcsaHmac.Canonical.string(
      conn.method,
      conn.request_path,
      get_header_value(conn, "date"),
      content_digest(conn, get_request_params(conn)),
      get_header_value(conn, "content-type")
    ))
    NcsaHmac.Canonical.string(
      conn.method,
      conn.request_path,
      get_header_value(conn, "date"),
      content_digest(conn, get_request_params(conn)),
      get_header_value(conn, "content-type")
    )
    IO.puts("-------------------------")
  end

  @doc """
  Compute the cryptographic signature from the canonical request string using
  the key_secret and hash_type specified in the function call.

  """
  def signature(conn, key_secret, hash_type \\ @default_hash) do
    Base.encode64(
      :crypto.hmac(hash_type, key_secret, canonicalize_conn(conn))
    )
  end

  @doc """
  Set the signature signature string which will be added to the `Authorization`
  header. Authorization string take the form:
  'NCSA.HMAC auth_id:base64_encoded_cryptograhic_signature'

  """
  def authorization(conn, key_id, key_secret, hash_type \\ @default_hash) do
    validate_key!(key_id, "key_id")
    validate_key!(key_secret, "key_secret")
    "#{@service_name} #{key_id}:#{signature(conn, key_secret, hash_type)}"
  end

  defp content_digest(_conn, ""), do: ""
  defp content_digest(conn, %Plug.Conn.Unfetched{aspect: :params}) do
    Base.encode16(:erlang.md5(conn.private.raw_body), case: :lower)
  end
  defp content_digest(_conn, params) when params == %{}, do: ""
  defp content_digest(_conn, params) do
    Base.encode16(:erlang.md5(normalize_parameters(params)), case: :lower)
  end

  defp set_header_date(conn) do
    case get_header_value(conn, "date") do
      [] -> Plug.Conn.put_req_header(conn, "date", set_date())
      _ -> conn
    end
  end

  defp get_header_value(conn, key) do
    Plug.Conn.get_req_header(conn, key)
  end

  defp get_request_params(conn) do
    case Map.has_key?(conn.params, "_json") do
      true -> conn.params["_json"]
      _ -> conn.params
    end
  end

  defp set_date do
    {_, iso_time} = Timex.Format.DateTime.Formatter.format(Timex.now, "{ISO:Extended:Z}")
    iso_time
  end

  defp set_headers(conn, key_id, key_secret, hash_type) do
    signature = authorization(conn, key_id, key_secret, hash_type)
    digest = content_digest(conn, conn.params)
    conn
      |> Plug.Conn.put_req_header("content-digest", digest)
      |> Plug.Conn.put_req_header("authorization", signature)
  end

  defp validate_key!(key, key_type) do
    case key do
      nil -> raise NcsaHmac.SigningError, message: "#{key_type} is required"
      "" -> raise NcsaHmac.SigningError, message: "#{key_type} is required"
      _ -> "carry on"
    end
  end

  # For interoperabiltiy, request parameters are converted to json and returned
  # in a deterministic order, so hash computation is unlikely to produce
  # different results on different systems.
  # For this reason we use the JSON package rather than Poision.
  defp normalize_parameters(params) do
    JSON.encode!(params)
  end
end
