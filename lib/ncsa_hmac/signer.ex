defmodule NcsaHmac.Signer do
  @default_hash :sha512
  @service_name "NCSA.HMAC"

  @moduledoc """
  The Signer module provides functions for signing a conn (web request) with a cryptographic algorithm.
  """

  @doc """
  Generate the complete signature for the request details

  Required paramters:

  * `:request_details` - A Map of the key elements from the request that are
  needed to compute a correct signature, must include: METHOD, PATH, PARAMS,
  and CONTENT-TYPE, optional values: DATE
  * `:key_id` - The database id of the record. This is also the publically
  visible and unencrypted piece of the request signature
  * `:key_secret` - The signing_key or sercret_key that is used to sign the request.
  This is the shared secret that must be known to both the requesting server
  as well as the receiveing server. The signing_key should be kept securely and
  not shared publically.

  Optional opts:

  * `:hash_type` - Specifies the cryptographic hash function to use when computing
  the signature.

  Set the signature signature string which will be added to the `Authorization`
  header. Authorization string take the form:
  'NCSA.HMAC auth_id:base64_encoded_cryptograhic_signature'

  """

  def sign(request_details, key_id, key_secret, hash_type \\ @default_hash) do
    validate_key!(key_id, "key_id")
    validate_key!(key_secret, "key_secret")
    "#{@service_name} #{key_id}:#{signature(request_details, key_secret, hash_type)}"
  end

  @doc """
  Create a canonical string from the request that will be used to computed
  the signature.

  The `canonicalize_request` method performs several steps:
  Set the `Date` field, unless it was already set.

  Calculate the MD5 Hash of the request parameters and set the `Content-Digest`
  field.

  Canonicalize the request fields. The helps ensure that only guaranteed fields
  are used to calculate the header. It also helps ensure that the same request
  signature will be calculated the same way every time.
  """

  def canonicalize_request(request_details) do
    request_details = request_details
    |> set_request_date
    |> Map.put("content-digest", content_digest(request_details["params"]))
    NcsaHmac.Canonical.string(
      request_details["method"],
      request_details["path"],
      request_details["date"],
      request_details["content-digest"],
      request_details["content-type"]
    )
  end

  @doc """
  Compute the cryptographic signature from the canonical request string using
  the key_secret and hash_type specified in the function call.

  """
  def signature(request_details, key_secret, hash_type \\ @default_hash) do
    Base.encode64(
      :crypto.hmac(hash_type, key_secret, canonicalize_request(request_details))
    )
  end

  @doc """
  For interoperabiltiy, request parameters are converted to json and returned
  in a deterministic order, so hash computation is unlikely to produce
  different results on different systems.
  For this reason we use the JSON package rather than Poision.
  """
  def normalize_parameters(params) when is_map(params) do
    case JSON.encode params do
      {:ok, json_params} -> json_params
      {:error, params} -> params
    end
  end
  def normalize_parameters(params), do: params

  defp content_digest(""), do: ""
  defp content_digest(params) when params == %{}, do: ""
  defp content_digest(params) do
    Base.encode16(:erlang.md5(normalize_parameters(params)), case: :lower)
  end

  defp set_request_date(request_details) do
    date = Map.get(request_details, "date")
    Map.put(request_details, "date", set_date(date))
  end

  defp set_date(nil) do
    {_, iso_time} = Timex.Format.DateTime.Formatter.format(Timex.now, "{ISO:Extended:Z}")
    iso_time
  end
  defp set_date(""), do: set_date(nil)
  defp set_date(date), do: date

  defp validate_key!(key, key_type) do
    case key do
      nil -> raise NcsaHmac.SigningError, message: "#{key_type} is required"
      "" -> raise NcsaHmac.SigningError, message: "#{key_type} is required"
      _ -> "carry on"
    end
  end
end
