defmodule NcsaHmac.CrossValidation.RubyTest do
  use ExUnit.Case
  use Export.Ruby
  alias RubyElixir.RubyCall
  alias NcsaHmac.Signer

  @method "post"
  @path "api/test"
  @params %{abc: "123"}
  @content_type "application/json"
  @public_key "public"
  @private_key "private"
  @date "Fri, 22 Jul 2016"


  test "Validate cryptographic signature against the Ey::Hmac library :sha256" do
    request_details = %{
      "path" => @path,
      "method" => @method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }

    hash_type = :sha256
    ey_signature = RubyCall.ruby_call(@method, @path, normalize_parameters, @content_type, @date, "", @public_key, @private_key, hash_type)

    ex_signature = Signer.signature(request_details, @private_key, hash_type)
    assert ey_signature == ex_signature
  end

  test "Validate cryptographic signature against the Ey::Hmac library :sha512" do
    request_details = %{
      "path" => @path,
      "method" => @method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }

    hash_type = :sha512
    ey_signature = RubyCall.ruby_call(@method, @path, normalize_parameters, @content_type, @date, "", @public_key, @private_key, hash_type)

    ex_signature = Signer.signature(request_details, @private_key, hash_type)
    assert ey_signature == ex_signature
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac signature" do
    request_details = %{
      "path" => @path,
      "method" => @method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }
    hash_type = :sha256

    ex_signature = Signer.sign(request_details, @public_key, @private_key, hash_type)
    ey_authenticated = RubyCall.ruby_call_request(@method, @path, normalize_parameters, @content_type, @date, nil, @public_key, @private_key, hash_type, ex_signature)
    assert ey_authenticated == true
  end

  defp normalize_parameters do
    Signer.normalize_parameters @params
  end
end
