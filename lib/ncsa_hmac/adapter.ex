defmodule NcsaHmac.Adapter do
  @default_hash :sha512
  @service_name "NCSA.HMAC"
  @adapter HTTPoison
  @moduledoc """
  The Adapter module provides functions for signing a web request
  with a cryptographic algorithm and sending that request using the HTTPoison
  library.
  Roadmap: Add support for additional HTTP adapter libs.
  """

  @doc """
    Sign GET requests with an HMAC authorization signature. Note, for GET
    requests, any query string appended to the end of the URL will be ignored
    in the signing process. This makes the query string succeptible to
    man-in-the-middle attacks.
    Function Arguments and Options
    params:
      * `:url` - REQUIRED, Must be fully qualified and compliant with `URI.parse`
      * `:headers` - OPTIONAL, A keyword list (orddict in erlang) or atom map.
      * `:body` - OPTIONAL, A keyword list (orddict in erlang) or atom map.
        Will be encoded to JSON using the JSON package.
      * `:opts` - REQUIRED, A keyword list (orddict in erlang) or atom map.
    opts params:
      * `:key_id` - REQUIRED, The non-secret id associated with the secret key
      * `:key_secret` - REQUIRED, The secret key used to sign the canonicalized request.
      * `:hash_type` - OPTIONAL, An atom representing the hash supported by the
        Erlang :crypto library. Defaults to :sha512
  """
  def get(url, headers \\ [], opts) do
    headers = sign!("GET", url, headers, opts)
    @adapter.get(url, headers)
  end

  @doc """
    Sign HEAD requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def head(url, headers \\ [], opts) do
    headers = sign!("HEAD", url, headers, opts)
    @adapter.head(url, headers)
  end

  @doc """
    Sign OPTIONS requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def options(url, headers \\ [], opts) do
    headers = sign!("OPTIONS", url, headers, opts)
    @adapter.options(url, headers)
  end

  @doc """
    Sign DELETE requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def delete(url, headers \\ [], opts) do
    headers = sign!("DELETE", url, headers, opts)
    @adapter.delete(url, headers, [])
  end

  @doc """
    Sign POST requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def post(url, body, headers \\ [], opts) do
    headers = sign!("POST", url, body, headers, opts)
    encoded = JSON.encode!(body)
    @adapter.post(url, encoded, headers, [])
  end

  @doc """
    Sign PUT requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def put(url, body, headers \\ [], opts) do
    headers = sign!("PUT", url, body, headers, opts)
    encoded = JSON.encode!(body)
    @adapter.put(url, encoded, headers, [])
  end

  @doc """
    Sign PATCH requests with an HMAC authorization signature.

    See Arguments and Options for a descrption of the parameters and
    options for this function.
  """
  def patch(url, body, headers \\ [], opts) do
    headers = sign!("PATCH", url, body, headers, opts)
    encoded = JSON.encode!(body)
    @adapter.patch(url, encoded, headers, [])
  end

  @doc """
  Sign the request and set header fields as needed. Though this function is public,
  it would be best not to use it. The HTTP VERB functions will properly set all
  the required headers and encode the request body as needed.

  The `sign!` method performs several steps:

  Set the `Date` header field, unless it was already set.

  Calculate the MD5 Hash of the body (request parameters) and set the `Content-Digest`
  header.

  Canonicalize the request fields. The helps ensure that only guaranteed fields
  are used to calculate the header. It also helps ensure that the same request
  signature will be calculated the same way every time.

  Parameters:
    * `:method` - A String in CAPS representing the HTTP method.
      EG GET or PATCH
    * `:url` - REQUIRED, Must be fully qualified and compliant with `URI.parse`
    * `:body` - OPTIONAL, A keyword list (orddict in erlang) or atom map.
      Will be encoded to JSON using the JSON package.
    * `:headers` - OPTIONAL, A keyword list (orddict in erlang) or atom map.
    * `:opts` - REQUIRED, A keyword list (orddict in erlang) or atom map.


    See Options for a descrption of the options for this function.
  """

  def sign!(method, url, headers, opts) do
    uri = parse(url)
    headers = process_headers(headers)
    |> Map.put("content-digest", "")
    |> set_auth_header(method, uri, opts)
  end

  def sign!(method, url, body, headers, opts) do
    uri = parse(url)
    headers = process_headers(headers)
    |> set_content_digest(body)
    |> set_auth_header(method, uri, opts)
  end

  @doc """
  See the NcsaHmac.Canonical module for information on how the request is canonicalized.
  """
  defp canonicalize(method, headers, uri) do
    NcsaHmac.Canonical.string(
      method,
      uri.path,
      headers["date"],
      headers["content-digest"],
      headers["content-type"]
    )
  end

  @doc """
  Compute the cryptographic signature from the canonical request string using
  the key_secret and hash_type specified in the function call.

  """
  defp signature(method, headers, uri, opts) do
    key_id = Keyword.get(opts, :key_id)
    key_secret = Keyword.get(opts, :key_secret)
    validate_key!(key_id, "key_id")
    validate_key!(key_secret, "key_secret")
    hash_type = Keyword.get(opts, :hash_type, @default_hash)

    canonical = canonicalize(method, headers, uri)
    hash = Base.encode64(:crypto.hmac(hash_type, key_secret, canonical))
    "#{@service_name} #{key_id}:#{hash}"
  end

  @doc """
  Set the signature signature string which will be added to the `Authorization`
  header. Authorization string take the form:
  'NCSA.HMAC key_id:base64_encoded_cryptograhic_signature'
  """
  defp set_auth_header(headers, method, uri, opts) do
    signature = signature(method, headers, uri, opts)
    Map.put(headers, "authorization", signature)
  end

  defp parse(url) do
    URI.parse(url)
  end

  defp process_headers(headers) when is_map(headers) do
    headers
    |> set_header_date()
    |> set_header_content_type()
  end

  defp process_headers(headers) when is_list(headers) do
    headers
    |> Enum.into(%{})
    |> process_headers()
  end

  defp set_content_digest(headers, body) when body == %{}, do: set_content_digest(headers, nil)
  defp set_content_digest(headers, ""), do: set_content_digest(headers, nil)
  defp set_content_digest(headers, nil) do
    headers
    |> Map.put("content-digest", "")
  end
  defp set_content_digest(headers, body) do
    md5_hash = Base.encode16(:erlang.md5(normalize_parameters(body)), case: :lower)
    headers
    |> Map.put("content-digest", md5_hash)
  end

  defp set_header_date(headers) do
    case headers["date"] do
      nil -> Map.put(headers, "date", set_date)
      _ -> headers
    end
  end

  defp set_date do
    {_, iso_time} = Timex.Format.DateTime.Formatter.format(Timex.now, "{ISO:Extended:Z}")
    iso_time
  end

  defp set_header_content_type(headers) do
    case headers["content-type"] do
      nil -> Map.put(headers, "content-type", "application/json")
      _ -> headers
    end
  end

  defp set_header_content_digest(headers) do
    case headers["date"] do
      nil -> Map.put(headers, "content-digest", "application/json")
      _ -> headers
    end
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
