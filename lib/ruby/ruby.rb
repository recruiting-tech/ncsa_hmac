require 'ey-hmac'
require 'ostruct'
require 'rack'
require 'JSON'
require 'stringio'
require 'openssl'

def signature(request_method, path, params, content_type, date, public_key, private_key, signing_hash = :sha512, options={})
  if params == nil || params == "" || params == :nil
    f = StringIO.new ""
    digest = ""
  else
    f = StringIO.new(params)
    digest = Digest::MD5.hexdigest(params)
  end

  request = Rack::Request.new("REQUEST_METHOD" => request_method, "CONTENT_TYPE" => content_type, "PATH_INFO" => path, "HTTP_CONTENT_DIGEST" => digest, "rack.input" => f, "HTTP_DATE" => date )
  ey = adapter.new(request, {sign_with: signing_hash, service: "NCSA.HMAC"})
  ey.signature(private_key, signing_hash).gsub("\n","")
end

def request(request_method, path, params, content_type, date, public_key, private_key, signing_hash = :sha512, options={}, elixir_signature)
  f = StringIO.new(params)
  digest = Digest::MD5.hexdigest(params)

  request = Rack::Request.new("REQUEST_METHOD" => request_method, "CONTENT_TYPE" => content_type, "PATH_INFO" => path, "rack.input" => f, "HTTP_DATE" => date, "HTTP_AUTHORIZATION" => elixir_signature )
  ey = adapter.new(request, {sign_with: signing_hash, service: "NCSA.HMAC"})

  Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
    (auth_id == public_key) && private_key
  end
end

def adapter
  Ey::Hmac::Adapter::Rack
end
