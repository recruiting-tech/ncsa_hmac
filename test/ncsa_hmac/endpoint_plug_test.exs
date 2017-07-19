defmodule NcsaHmac.EndpointPlugTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import NcsaHmac.EndpointPlug

  @moduletag timeout: 100000000
  @req_signature "Something 1:a_signature"
  @date "Fri, 22 Jul 2016"
  @content_type "application/json"
  @key_id "some_auth_id"
  @signing_key "some_signing_key"

  describe "authorize_resource/2" do
    test "it assigns the unparsed request body to :raw_body" do
      opts = [model: ApiKey, only: :some_action, id_field: "auth_id"]
      req_signature = NcsaHmac.Signer.sign(%{"params" => "", "method" => "post", "date" => @date, "path" => "/api/auth", "content-type" => "application/json"}, @key_id, @signing_key)

      conn = conn(:post, "/api/auth")
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: @key_id, signing_key: @signing_key})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", req_signature)

      actual = authorize_resource(conn, opts)
      assert actual.private.raw_body == ""
      assert actual.private.auth_id == @key_id
    end

    test "catches the exception and returns a 401 with a message when authorization key is absent " do
      opts = [model: ApiKey, id_name: "post_id"]
      params = %{"post_id" => 1}
      conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
      |> authorize_resource(opts)

      assert conn.status == 401
      refute conn.assigns.authorized
      error_message = "Failed to parse authorization_signature: nil"
      assert conn.assigns.error_message == error_message
      error_body = "{\"errors\":[{\"detail\":\"#{error_message}\",\"message\":\"Unauthorized\"}]}"
      assert conn.resp_body == error_body
    end

    test "halt execution when authorization fails" do
      opts = [model: ApiKey, id_name: "post_id"]
      params = %{"post_id" => 1}
      conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
      |> Plug.Conn.put_req_header("authorization", @req_signature)

      sent = authorize_resource(conn, opts)
      assert sent.state == :sent
      assert sent.status == 401
    end
  end

  describe "init/1 and call/2" do
    test "The plug module :call works without exceptions" do
      conn = conn(:post, "/some/path")
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @req_signature)

      opts = default_opts(%{mount: ["some", "path"], model: ApiKey})
      NcsaHmac.EndpointPlug.call(conn, opts)
    end

    test "The plug module returns the conn when the path is different" do
      conn = conn(:post, "/some/path")
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @req_signature)

      opts = default_opts(%{mount: ["some", "other", "path"], model: ApiKey})
      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      assert conn.status == nil
      assert conn.state == :unset
      assert conn.assigns == %{}
      assert conn.private == %{}
    end

    test "The plug module only matches :mount to the beginning of the path and ignores anything after" do
      conn = conn(:post, "/some/path/with/additional/params")
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @req_signature)

      opts = default_opts(%{mount: ["some", "path", "with"], model: ApiKey})
      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      assert conn.status == 401
      refute conn.assigns.authorized
      error_message = "The signature authorization_id does not match any records. auth_id: 1"
      assert conn.assigns.error_message == error_message
      error_body = "{\"errors\":[{\"detail\":\"#{error_message}\",\"message\":\"Unauthorized\"}]}"
      assert conn.resp_body == error_body
    end

    test "The plug module returns a 401 without authentication" do
      conn = conn(:post, "/some/path")
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @req_signature)

      opts = default_opts(%{mount: ["some", "path"], model: ApiKey})
      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      assert conn.status == 401
      refute conn.assigns.authorized
      error_message = "The signature authorization_id does not match any records. auth_id: 1"
      assert conn.assigns.error_message == error_message
      error_body = "{\"errors\":[{\"detail\":\"#{error_message}\",\"message\":\"Unauthorized\"}]}"
      assert conn.resp_body == error_body
    end

    test "The plug module returns a 401 when the signature is missing" do
      conn = conn(:post, "/some/path")
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", "")

      opts = default_opts(%{mount: ["some", "path"], model: ApiKey})
      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      assert conn.status == 401
      refute conn.assigns.authorized
      error_message = "Failed to parse authorization_signature: "
      assert conn.assigns.error_message == error_message
      error_body = "{\"errors\":[{\"detail\":\"#{error_message}\",\"message\":\"Unauthorized\"}]}"
      assert conn.resp_body == error_body
    end

    test "The authentication works via :call" do
      params = %{"post_id" => 1}
      request_details = %{"method" => "POST", "date" => @date, "content-type" => "application/json", "path" => "/some/path", "params" => params}

      signature = NcsaHmac.Signer.sign(request_details, "auth_id_valid", "signing_key")
      opts = default_opts(%{mount: ["some", "path"], model: ApiKey})
      conn = conn(:post, "/some/path", params)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", signature)
      |> call(opts)

      refute conn.status == 401
      assert conn.assigns.authorized
      assert conn.private.auth_id == "auth_id_valid"
    end

    test "The authentication works with a partial path match" do
      params = %{"post_id" => 1}
      request_details = %{"method" => "POST", "date" => @date, "content-type" => "application/json", "path" => "/some/path/with/additional/params", "params" => params}

      signature = NcsaHmac.Signer.sign(request_details, "auth_id_valid", "signing_key")
      opts = default_opts(%{mount: ["some", "path", "with"], model: ApiKey})
      conn = conn(:post, "/some/path/with/additional/params", params)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", signature)

      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      refute conn.status == 401
      assert conn.assigns.authorized
      assert conn.private.auth_id == "auth_id_valid"
    end

    test "The opts[:repo] is used first." do
      Application.delete_env :ncsa_hmac, :repo
      opts = default_opts(%{mount: ["some", "path", "with"], model: ApiKey, repo: Repo})

      params = %{"post_id" => 1}
      request_details = %{"method" => "POST", "date" => @date, "content-type" => "application/json", "path" => "/some/path/with/additional/params", "params" => params}

      signature = NcsaHmac.Signer.sign(request_details, "auth_id_valid", "signing_key")
      conn = conn(:post, "/some/path/with/additional/params", params)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", signature)

      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      refute conn.status == 401
      assert conn.assigns.authorized
      assert conn.private.auth_id == "auth_id_valid"
      Application.put_env :ncsa_hmac, :repo, Repo
    end

    test "The opts[:repo] overrides the Application repo." do
      Application.put_env :ncsa_hmac, :repo, NcsaHmac.Signer
      opts = default_opts(%{mount: ["some", "path", "with"], model: ApiKey, repo: Repo})

      params = %{"post_id" => 1}
      request_details = %{"method" => "POST", "date" => @date, "content-type" => "application/json", "path" => "/some/path/with/additional/params", "params" => params}

      signature = NcsaHmac.Signer.sign(request_details, "auth_id_valid", "signing_key")
      conn = conn(:post, "/some/path/with/additional/params", params)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", signature)

      conn = NcsaHmac.EndpointPlug.call(conn, opts)
      refute conn.status == 401
      assert conn.assigns.authorized
      assert conn.private.auth_id == "auth_id_valid"
      Application.put_env :ncsa_hmac, :repo, Repo
    end
  end

  defp default_opts(opts) do
    # The :init fn is called at compile time for us. To test the :call fn,
    # we need to make the :init call manually.
    NcsaHmac.EndpointPlug.init(opts)
  end
end
