
defmodule NcsaHmac.PlugTest do
  Code.load_file("test/support/repo_setup.ex")
  use ExUnit.Case, async: true
  use Plug.Test
  import NcsaHmac.Plug

  @moduletag timeout: 100000000

  Application.put_env :ncsa_hmac, :repo, Repo

  test "it loads the db resource correctly in different scenarios" do
    opts = [model: ApiKey]

    # when the resource with the id can be fetched
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 1})}
    assert load_resource(conn, opts) == expected

    # when a resource of the desired type is already present in conn.assigns
    # it does not clobber the old resource
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 2})
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 2})}
    assert load_resource(conn, opts) == expected

    # when a resource of a different type is already present in conn.assigns
    # it replaces that resource with the desired resource
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
      |> Plug.Conn.assign(:api_key, %User{id: 2})

    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 1})}
    assert load_resource(conn, opts) == expected

    # when the resource with the id cannot be fetched
    params = %{"id" => 3}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, nil)}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly with opts[:id_name] specified" do
    opts = [model: ApiKey, id_name: "post_id"]

    # when id param is correct
    params = %{"post_id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 1})}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly with opts[:id_field] specified" do
    opts = [model: ApiKey, id_name: "auth_id", id_field: "auth_id"]

    # when auth_id param is correct
    params = %{"auth_id" => "auth_id1"}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 1, auth_id: "auth_id1"})}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly and gets the key field" do
    opts = [model: ApiKey, id_name: "auth_id", id_field: "auth_id", key_field: "signing_key"]

    # when auth_id param is correct
    params = %{"auth_id" => "auth_id_valid"}
    conn = conn(:get, "/posts/", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :api_key, %ApiKey{id: 11, auth_id: "auth_id_valid", signing_key: "signing_key"})}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource into a key specified by the :as option" do
    opts = [model: ApiKey, as: :secret_key, id_name: "auth_id", id_field: "auth_id"]

    # when auth_id param is correct
    params = %{"auth_id" => "auth_id_valid"}
    conn = conn(:get, "/posts/", params)
      |> Plug.Conn.assign(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :secret_key, %ApiKey{id: 11, auth_id: "auth_id_valid", signing_key: "signing_key"})}
    assert load_resource(conn, opts) == expected
  end

  @key_id "auth_id1"
  @signing_key "base64_signing_key"
  @target_body %{"auth_id" => "auth_id1"}
  @expected_sha512_signature "1UldRTPlTEkh1uDhVNvpB+XFgeM0OCN8uzx8+F3Xfg2QmBi02TGQI4Y58zk0AfqY20ds7NHOSWrOojORpBcG3w=="
  @date "Fri, 22 Jul 2016"
  @content_type "application/json"
  @opts [model: ApiKey, id_name: "auth_id", id_field: "auth_id", key_field: "signing_key"]
  @valid_auth_string "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature

  test "it verifies the request signature and authorizes when signature is valid" do
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)

    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert authorize_resource(conn, @opts) == expected
  end

  test "it invalidates the request when authorization header is absent" do
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})

    expected = Plug.Conn.assign(conn, :authorized, false)
      |> Plug.Conn.assign(:error_message, "Failed to parse authorization_signature: nil")
      |> Plug.Conn.assign(:api_key, nil)
    assert authorize_resource(conn, @opts) == expected
  end

  test "it invalidates the request signature and authorizes when signature is invalid" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":invalid_signature"
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    invalid_signature_message = "Error: computed signature does not match header signature: invalid_signature"
    expected = Plug.Conn.assign(conn, :authorized, false)
      |> Plug.Conn.assign(:error_message, invalid_signature_message)
      |> Plug.Conn.assign(:api_key, nil)
    assert authorize_resource(conn, @opts) == expected
  end

  test "it removes the resource when signature is invalid" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":invalid_signature"
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    invalid_signature_message = "Error: computed signature does not match header signature: invalid_signature"
    expected = Plug.Conn.assign(conn, :authorized, false) |> Plug.Conn.assign(:error_message, invalid_signature_message)
    expected = %{expected | assigns: Map.put(expected.assigns, :api_key, nil)}
    assert load_and_authorize_resource(conn, @opts) == expected
  end

  test "it loads and authorizes the resource correctly" do
    opts = [model: ApiKey]
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    # when the resource with the id can be fetched
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected

    # when the resource with the id cannot be fetched
    auth_string = "NCSA.HMAC " <> "909090" <> ":" <> "also_the_signature_is_invalid"
    conn = conn(:post, "/api/auth", %{"auth_id" => "909090"})
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, nil)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    invalid_signature_message = "The signature authorization_id does not match any records. auth_id: 909090"
    expected = Plug.Conn.assign(conn, :authorized, false) |> Plug.Conn.assign(:error_message, invalid_signature_message)
    expected = %{expected | assigns: Map.put(expected.assigns, :api_key, nil)}
    assert load_and_authorize_resource(conn, opts) == expected
  end

  test "it loads and authorizes the resource with only the signature auth_id" do
    opts = [model: ApiKey]
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    # when the resource with the id can be fetched
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected

    # when the resource with the id cannot be fetched
    auth_string = "NCSA.HMAC " <> "909090" <> ":" <> "also_the_signature_is_invalid"
    conn = conn(:post, "/api/auth", %{"auth_id" => "909090"})
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, nil)
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    invalid_signature_message = "The signature authorization_id does not match any records. auth_id: 909090"
    expected = Plug.Conn.assign(conn, :authorized, false) |> Plug.Conn.assign(:error_message, invalid_signature_message)
    expected = %{expected | assigns: Map.put(expected.assigns, :api_key, nil)}
    assert load_and_authorize_resource(conn, opts) == expected
  end

  test "it authorizes the resource correctly when using :id_field options" do
    opts = [model: ApiKey, id_name: "auth_id", id_field: "auth_id"]
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected

    # when the resource with the id cannot be fetched
    conn = conn
      |> Plug.Conn.assign(:api_key, nil)

    invalid_signature_message = "The signature authorization_id does not match any records. auth_id: auth_id1"
    expected = Plug.Conn.assign(conn, :authorized, false)
      |> Plug.Conn.assign(:error_message, invalid_signature_message)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected
  end

  test "it loads and authorizes the resource correctly when using :id_field and key_field options" do
    opts = [model: ApiKey, id_name: "auth_id", id_field: "auth_id", key_field: "slug"]

    # when the key_field on the resource is valid
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", slug: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected

    # when the signing key_field on the resource is invalid
    conn = conn
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", slug: "the_wrong_base64_signing_key"})

    invalid_signature_message = "Error: computed signature does not match header signature: #{@expected_sha512_signature}"
    expected = Plug.Conn.assign(conn, :authorized, false)
      |> Plug.Conn.assign(:error_message, invalid_signature_message)
      |> Plug.Conn.assign(:api_key, nil)

    assert load_and_authorize_resource(conn, opts) == expected
  end

  test "it only authorizes actions in opts[:only]" do
    opts = [model: ApiKey, only: :some_action]
    #when the action is the :only action
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert authorize_resource(conn, opts) == expected

    #when the only: action is stored under the :phoenix_action key
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:phoenix_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert authorize_resource(conn, opts) == expected

    #when the action is not the :only action
    conn = conn
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 123})
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_other_action)

    expected = conn
    assert authorize_resource(conn, opts) == expected
  end

  test "it only loads_and_authorizes actions in opts[:only]" do
    opts = [model: ApiKey, only: :some_action]

    #when the action is the :only action
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected

    #when the action is not the :only action
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_other_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 123})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = conn
    assert load_and_authorize_resource(conn, opts) == expected
  end

  test "it skips the plug when both opts[:only] and opts[:except] are specified" do
    opts = [model: ApiKey, only: :some_action, except: :some_other_action]
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_other_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 123})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)

    assert load_resource(conn, opts) == conn
    assert authorize_resource(conn, opts) == conn
    assert load_and_authorize_resource(conn, opts) == conn
  end

  test "it correctly skips authorization for execept actions" do
    opts = [model: ApiKey, except: :some_other_action]
    #when the action is not execepted
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)

    assert load_and_authorize_resource(conn, opts) == expected
    assert authorize_resource(conn, opts) == expected
    assert load_resource(conn, opts) == conn

    #when the action is execepted
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_other_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 123})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", @valid_auth_string)

    assert load_and_authorize_resource(conn, opts) == conn
    assert authorize_resource(conn, opts) == conn
    assert load_resource(conn, opts) == conn
  end

  test "it handles auth_id missing from the request body" do
    opts = [model: ApiKey, only: :some_action]
    req_signature = NcsaHmac.Signer.sign(%{"params" => %{}, "method" => "post", "date" => @date, "path" => "/api/auth", "content-type" => "application/json"}, @key_id, @signing_key)
    conn = conn(:post, "/api/auth", %{})
      |> Plug.Conn.assign(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %ApiKey{id: 1, auth_id: @key_id, signing_key: @signing_key})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", req_signature)
    expected = Plug.Conn.assign(conn, :authorized, true)
      |> Plug.Conn.assign(:api_key, nil)
    assert load_and_authorize_resource(conn, opts) == expected
  end
end
