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
  @hash_type :sha256

  test "Validate cryptographic signature against the Ey::Hmac library :sha256" do
    request_details = %{
      "path" => @path,
      "method" => @method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }

    ey_signature = RubyCall.ruby_call(@method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type)

    ex_signature = Signer.signature(request_details, @private_key, @hash_type)
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
    ey_signature = RubyCall.ruby_call(@method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, hash_type)

    ex_signature = Signer.signature(request_details, @private_key, hash_type)
    assert ey_signature == ex_signature
  end

  test "Validate cryptographic signature for HTTP_GET against the Ey::Hmac library :sha256" do
    query_string = "?abc='123'"
    concat_path = @path <> query_string
    request_details = %{
      "path" => concat_path,
      "method" => "get",
      "params" => "something to get sliced off",
      "query_string" => query_string,
      "date" => @date,
      "content-type" => @content_type,
    }

    ey_signature = RubyCall.ruby_call("get", concat_path, nil, @content_type, @date, @public_key, @private_key, @hash_type)

    ex_signature = Signer.signature(request_details, @private_key, @hash_type)
    assert ey_signature == ex_signature
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac POST signature" do
    request_details = %{
      "path" => @path,
      "method" => @method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }

    ex_signature = Signer.sign(request_details, @public_key, @private_key, @hash_type)
    ey_authenticated = RubyCall.ruby_call_request(@method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type, ex_signature)
    assert ey_authenticated == true
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac PUT signature" do
    request_details = %{
      "path" => @path,
      "method" => "put",
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type,
    }

    ex_signature = Signer.sign(request_details, @public_key, @private_key, @hash_type)
    ey_authenticated = RubyCall.ruby_call_request("put", @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type, ex_signature)
    assert ey_authenticated == true
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac GET signature" do
    query_string = "?abc='123'"
    concat_path = @path <> query_string
    request_details = %{
      "path" => concat_path,
      "method" => "get",
      "params" => "something to get sliced off",
      "query_string" => query_string,
      "date" => @date,
      "content-type" => @content_type,
    }

    ex_signature = Signer.sign(request_details, @public_key, @private_key, @hash_type)
    ey_authenticated = RubyCall.ruby_call_request("get", concat_path, "", @content_type, @date, @public_key, @private_key, @hash_type, ex_signature)
    assert ey_authenticated == true
  end

  defp normalize_parameters do
    Signer.normalize_parameters @params
  end
end
