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

  test "POST, Validate cryptographic signature against the Ey::Hmac library :sha256" do
    validate_signature("POST", :sha256)
  end

  test "PUT, Validate cryptographic signature against the Ey::Hmac library :sha256" do
    validate_signature("PUT", :sha256)
  end

  test "PATCH, Validate cryptographic signature against the Ey::Hmac library :sha256" do
    validate_signature("PATCH", :sha256)
  end

  test "DELETE, Validate cryptographic signature against the Ey::Hmac library :sha256" do
    validate_signature("DELETE", :sha256)
  end

  test "HEAD, Validate cryptographic signature against the Ey::Hmac library :sha256" do
    validate_signature("HEAD", :sha256)
  end

  test "POST, Validate cryptographic signature against the Ey::Hmac library :sha512" do
    validate_signature("POST", :sha512)
  end

  test "PUT, Validate cryptographic signature against the Ey::Hmac library :sha512" do
    validate_signature("PUT", :sha512)
  end

  test "PATCH, Validate cryptographic signature against the Ey::Hmac library :sha512" do
    validate_signature("PATCH", :sha512)
  end

  test "DELETE, Validate cryptographic signature against the Ey::Hmac library :sha512" do
    validate_signature("DELETE", :sha512)
  end

  test "HEAD, Validate cryptographic signature against the Ey::Hmac library :sha512" do
    validate_signature("HEAD", :sha512)
  end

  test "GET Validate cryptographic signature against the Ey::Hmac library :sha256" do
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

  test "GET Validate cryptographic signature against the Ey::Hmac library :sha512" do
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
    ey_signature = RubyCall.ruby_call("get", concat_path, nil, @content_type, @date, @public_key, @private_key, :sha512)
    ex_signature = Signer.signature(request_details, @private_key, :sha512)

    assert ey_signature == ex_signature
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac GET request" do
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
    ey_authenticated = RubyCall.ruby_call_authenticate("get", concat_path, "", @content_type, @date, @public_key, @private_key, @hash_type, ex_signature)

    assert ey_authenticated == true
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac POST request" do
    authenticate("POST")
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac PUT request" do
    authenticate("PUT")
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac PATCH request" do
    authenticate("patch")
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac DELETE request" do
    authenticate("DELETE")
  end

  test "Check the Ey::Hmac lib can authenticate an NcsaHmac HEAD request" do
    authenticate("HEAD")
  end

  test "Validate signature with multiple request parameters PUT request" do
    method = "PUT"
    params = %{email: "user@school.edu", iped: "2345"}
    request_details = %{"path" => @path,
      "method" => method,
      "params" => params,
      "date" => @date,
      "content-type" => @content_type
    }

    normalize_parameters = Signer.normalize_parameters params
    ey_signature = RubyCall.ruby_call(method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type)
    ex_signature = Signer.signature(request_details, @private_key, @hash_type)

    assert ey_signature == ex_signature
  end

  test "Validate signature with multiple parameters PUT request" do
    method = "PUT"
    params = %{email: "user@school.edu", iped: 2345}
    request_details = %{"path" => @path,
      "method" => method,
      "params" => params,
      "date" => @date,
      "content-type" => @content_type
    }

    normalize_parameters = Signer.normalize_parameters params
    ey_signature = RubyCall.ruby_call(method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type)
    ex_signature = Signer.signature(request_details, @private_key, @hash_type)

    assert ey_signature == ex_signature
  end

  test "Validate signature with multiple request parameters and string keys PUT" do
    method = "PUT"
    params = %{"email" => "user@school.edu", "iped" => "2345"}
    request_details = %{"path" => @path,
      "method" => method,
      "params" => params,
      "date" => @date,
      "content-type" => @content_type
    }

    normalize_parameters = Signer.normalize_parameters params
    ey_signature = RubyCall.ruby_call(method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type)
    ex_signature = Signer.signature(request_details, @private_key, @hash_type)

    assert ey_signature == ex_signature
  end

  defp validate_signature(method, hash_type) do
    request_details = request_details(method)
    ey_signature = RubyCall.ruby_call(method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, hash_type)
    ex_signature = Signer.signature(request_details, @private_key, hash_type)

    assert ey_signature == ex_signature
  end

  defp authenticate(method) do
    request_details = request_details(method)
    ex_signature = Signer.sign(request_details, @public_key, @private_key, @hash_type)
    ey_authenticated = RubyCall.ruby_call_authenticate(method, @path, normalize_parameters, @content_type, @date, @public_key, @private_key, @hash_type, ex_signature)

    assert ey_authenticated == true
  end

  defp normalize_parameters do
    Signer.normalize_parameters @params
  end

  defp request_details(method) do
    %{"path" => @path,
      "method" => method,
      "params" => @params,
      "date" => @date,
      "content-type" => @content_type
    }
  end
end
