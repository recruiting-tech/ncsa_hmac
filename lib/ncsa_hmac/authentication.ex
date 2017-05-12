defmodule NcsaHmac.Authentication do
  alias NcsaHmac.PlugConnSigner
  @authorization_regexp ~r/\w+ ([^:]+):(.+)$/
  @accepted_algorithms [:sha512, :sha384, :sha256]

  @moduledoc """
  The Authentication module provides functions for validating an HMAC signature on a web request.
  """

  @doc """
  Authenticate the header 'Authorization' signature.

  The `authenticate!` method performs several steps first:

  Load the resource with id/auth_id given extracted from the 'Authorization' signature.

  Get the `signing_key` from the resource.

  Determine, which if any of the currently accepted cyptographic algorithms: #{inspect @accepted_algorithms}
  was used to sign the request.

  Pass the request (conn) to the Signer module to calculate a signature and
  compare the computed signature to the signature sent with the request.
  If any of the elements used to compute the signature changed between when the
  request was signed and received, the `authenticate!` will fail.

  Requests coming in to get authenticated must include the `Date` header field.
  If the `Date` field is absent, the Signer module will set the `Date` field and
  the reuqest will never be able to authenticate.

  Required opts:

  * `:model` - Specifies the module name of the model to load resources from

  Optional opts:

  * `:as` - Specifies the `resource_name` to use
  * `:only` - Specifies which actions to authorize
  * `:except` - Specifies which actions for which to skip authorization
  * `:id_name` - Specifies the name of the id in `conn.params`, defaults to "id"
  * `:id_field` - Specifies the name of the ID field in the database for searching :id_name value, defaults to "id".
  * `:key_field` - Specifies the name of the signing_key field in the database for searching, defaults to "signing_key".
  * `:not_found_handler` - Specify a handler function to be called if the resource is not found
  """

  def authenticate!(conn, opts) do
    try do
      auth_signature = Enum.at(Plug.Conn.get_req_header(conn, "authorization"),0)
      [auth_id, signature] = unpack_signature!(auth_signature)
      signing_key = signing_key(conn, opts, auth_id)
      verify_signature!(conn, signature, signing_key)
    rescue
      e in NcsaHmac.AuthorizationError -> {:error, e.message}
    end
  end

  def auth_id(conn, opts) do
    [auth_id, _] = Enum.at(Plug.Conn.get_req_header(conn, "authorization"),0)
    |> unpack_signature!
    auth_id
  end

  defp unpack_signature!(nil), do: authorization_error("Failed to parse authorization_signature: nil")
  defp unpack_signature!(signature) do
    auth_match = String.match?(signature, @authorization_regexp)
    unless auth_match do authorization_error("Failed to parse authorization_signature: #{signature}") end
    parse_key_signature(signature)
  end

  defp parse_key_signature(signature) do
    auth_list = String.split("#{signature}")
    String.split(Enum.at(auth_list, 1), ":", parts: 2)
  end

  defp signing_key(conn, opts, auth_id) do
    signing_key = case opts[:key_field] do
      nil -> :signing_key
      "" -> :signing_key
      _ -> String.to_atom(opts[:key_field])
    end
    key_map = resource(conn, opts, auth_id)
      |> Map.take([signing_key])
    resource_signing_key = key_map[signing_key]
    unless resource_signing_key do
      authorization_error "The signature authorization_id does not match any records. auth_id: #{auth_id}"
    end
    resource_signing_key
  end

  defp resource(conn, opts, auth_id) do
    resource = conn.assigns[resource_name(opts)] || conn.assigns[:api_key]
    unless resource do
      authorization_error "The signature authorization_id does not match any records. auth_id: #{auth_id}"
    end
    resource
  end

  defp verify_signature!(conn, signature, signing_key) do
    valid_algorithm = Enum.reject(@accepted_algorithms, fn(algo) ->
      signature != PlugConnSigner.signature(conn, signing_key, algo)
    end)
    #Calculate and compare the signature again, so we don't return true by default
    validate_signature(conn, signature, signing_key, valid_algorithm)
  end

  defp validate_signature(_, signature, _, []) do
    authorization_error "Error: computed signature does not match header signature: #{signature}"
  end
  defp validate_signature(conn, signature, signing_key, algorithm) do
    {:ok, signature == PlugConnSigner.signature(conn, signing_key, Enum.at(algorithm, 0))}
  end

  defp authorization_error(message) do
    raise NcsaHmac.AuthorizationError, message: message
  end

  defp resource_name(opts) do
    NcsaHmac.Plug.resource_name(opts)
  end
end
