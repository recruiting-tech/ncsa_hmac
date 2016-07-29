defmodule User do
  defstruct id: 1
end

defmodule Post do
  use Ecto.Schema

  schema "posts" do
    field :user_id, :integer, default: 1
    field :slug, :string
    field :auth_id, :string
    field :signing_key, :string
  end
end

defmodule Repo do
  def get(Post, 1), do: %Post{id: 1}
  def get(Post, 2), do: %Post{id: 2}
  def get(Post, _), do: nil
  def all(_), do: [%Post{id: 1}, %Post{id: 2}]
  def get_by(Post, %{id: 1}), do: %Post{id: 1}
  def get_by(Post, %{id: 2}), do: %Post{id: 2}
  def get_by(Post, %{id: _}), do: nil

  def get_by(Post, %{slug: "slug1"}), do: %Post{id: 1, slug: "slug1"}
  def get_by(Post, %{slug: "slug2"}), do: %Post{id: 2, slug: "slug2"}
  def get_by(Post, %{slug: _}), do: nil
  def get_by(Post, %{auth_id: "auth_id1"}), do: %Post{id: 1, auth_id: "auth_id1"}
  def get_by(Post, %{auth_id: "auth_id2"}), do: %Post{id: 2, auth_id: "auth_id2"}
  def get_by(Post, %{auth_id: "auth_id11"}), do: %Post{id: 1, auth_id: "auth_id11", signing_key: "signing_key"}
  def get_by(Post, %{auth_id: _}), do: nil
end

defmodule NcsaHmac.PlugTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import NcsaHmac.Plugs

  @moduletag timeout: 100000000

  Application.put_env :ncsa_hmac, :repo, Repo

  test "it loads the db resource correctly in different scenarios" do
    opts = [model: Post]

    # when the resource with the id can be fetched
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 1})}
    assert load_resource(conn, opts) == expected

    # when a resource of the desired type is already present in conn.assigns
    # it does not clobber the old resource
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
      |> Plug.Conn.assign(:post, %Post{id: 2})
    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 2})}
    assert load_resource(conn, opts) == expected
    # IO.inspect conns

    # when a resource of a different type is already present in conn.assigns
    # it replaces that resource with the desired resource
    params = %{"id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
      |> Plug.Conn.assign(:post, %User{id: 2})

    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 1})}
    assert load_resource(conn, opts) == expected

    # when the resource with the id cannot be fetched
    params = %{"id" => 3}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :post, nil)}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly with opts[:id_name] specified" do
    opts = [model: Post, id_name: "post_id"]

    # when id param is correct
    params = %{"post_id" => 1}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 1})}

    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly with opts[:id_field] specified" do
    opts = [model: Post, id_name: "auth_id", id_field: "auth_id"]

    # when auth_id param is correct
    params = %{"auth_id" => "auth_id1"}
    conn = conn(:get, "/posts/1", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 1, auth_id: "auth_id1"})}
    assert load_resource(conn, opts) == expected
  end

  test "it loads the resource correctly and gets the key field" do
    opts = [model: Post, id_name: "auth_id", id_field: "auth_id", key_name: "signing_key"]

    # when auth_id param is correct
    params = %{"auth_id" => "auth_id11"}
    conn = conn(:get, "/posts/", params)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :show)
    expected = %{conn | assigns: Map.put(conn.assigns, :post, %Post{id: 1, auth_id: "auth_id11", signing_key: "signing_key"})}
    assert load_resource(conn, opts) == expected
  end

  @key_id "auth_id1"
  @signing_key "base64_signing_key"
  @target_body %{"auth_id" => "auth_id1"}
  @expected_sha512_signature "1UldRTPlTEkh1uDhVNvpB+XFgeM0OCN8uzx8+F3Xfg2QmBi02TGQI4Y58zk0AfqY20ds7NHOSWrOojORpBcG3w=="
  @date "Fri, 22 Jul 2016"
  @content_type "application/json"
  @opts [model: Post, id_name: "auth_id", id_field: "auth_id", key_name: "signing_key"]

  test "it verifies the request signature and authorizes when signature is valid" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %Post{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    expected = %{conn | assigns: Map.put(conn.assigns, :authorized, true)}
    assert authorize_resource(conn, @opts) == expected
  end

  test "it invalidates the request signature and authorizes when signature is invalid" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":invalid_signature"
    conn = conn(:post, "/api/auth", @target_body)
      |> Plug.Conn.put_private(:ncsa_hmac_action, :some_action)
      |> Plug.Conn.assign(:api_key, %Post{id: 1, auth_id: "auth_id1", signing_key: "base64_signing_key"})
      |> Plug.Conn.put_req_header("content-type", @content_type)
      |> Plug.Conn.put_req_header("date", @date)
      |> Plug.Conn.put_req_header("authorization", auth_string)

    invalid_signature_message = "Error: computed signature does not match header signature: invalid_signature"
    expected = Plug.Conn.assign(conn, :authorized, false) |> Plug.Conn.assign(:error_message, invalid_signature_message)
    assert authorize_resource(conn, @opts) == expected
  end
end
