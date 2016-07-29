defmodule NcsaHmac.Authentication do
  alias NcsaHmac.Signer

  @authorization_regexp ~r/\w+ ([^:]+):(.+)$/
  @accepted_algorithms [:sha512, :sha384, :sha256]

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
    signing_key = opts[:signing_key] || :signing_key
    resource_signing_key = resource(conn, opts, auth_id).signing_key
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
      signature != Signer.signature(conn, signing_key, algo)
    end)
    #Calculate and compare the signature again, so we don't return true by default
    validate_signature(conn, signature, signing_key, valid_algorithm)
  end

  defp validate_signature(conn, signature, signing_key, []) do
    authorization_error "Error: computed signature does not match header signature: #{signature}"
  end
  defp validate_signature(conn, signature, signing_key, algorithm) do
    {:ok, signature == Signer.signature(conn, signing_key, Enum.at(algorithm, 0))}
  end

  defp authorization_error(message) do
    raise NcsaHmac.AuthorizationError, message: message
  end

  defp resource_name(opts) do
    NcsaHmac.Plugs.resource_name(opts)
  end
end
