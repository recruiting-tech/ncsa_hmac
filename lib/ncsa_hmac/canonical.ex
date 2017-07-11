defmodule NcsaHmac.Canonical do

  @moduledoc """
  The Canonical module provides a single public function to generate the canoical string.
  """

  @doc """
  Create a canonical string from the request that will be used to computed
  the signature. GET request must be canoncalized correctly using only the base path
  and ignoring both the query string and params that Plug.Conn adds when it
  parses the query_string.
  """
  def string(method, path, date, content_digest \\ "", content_type \\ "application/json")
  def string(method, path, date, content_digest, content_type) do
    Enum.join([
      String.upcase(method),
      content_type,
      content_digest(method, content_digest) ,
      date,
      String.downcase(path)
      ], "\n")
  end

  defp content_digest(method, content_digest) do
    case method do
      "GET" -> ""
      _ -> content_digest
    end
  end
end
