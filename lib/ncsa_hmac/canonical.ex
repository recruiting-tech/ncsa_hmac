defmodule NcsaHmac.Canonical do
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
