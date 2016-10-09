defmodule RubyElixir.RubyCall do
  use Export.Ruby

  def ruby_call(request_method, path, params, content_type, date, public_key, private_key, signing_hash) do
    {:ok, ruby} = Ruby.start(ruby_lib: Path.expand("lib/ruby"))
    ruby
    |> Ruby.call("ruby", "signature", [request_method, path, params, content_type, date, public_key, private_key, signing_hash])
  end

  def ruby_call_request(request_method, path, params, content_type, date, public_key, private_key, signing_hash, elixir_signature) do
    {:ok, ruby} = Ruby.start(ruby_lib: Path.expand("lib/ruby"))
    ruby
    |> Ruby.call("ruby", "request", [request_method, path, params, content_type, date, public_key, private_key, signing_hash, elixir_signature])
  end
end
