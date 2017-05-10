defmodule NcsaHmac.Plug do
  import Ecto.Query
  import Keyword, only: [has_key?: 2]

  @moduledoc """
  Plug functions for loading and authorizing resources for the current request.

  The plugs all store data in conn.assigns (in Phoenix applications, keys in conn.assigns can be accessed with `@key_name` in templates)

  You must also specify the Ecto repo to use in your configuration:
  ```
  config :ncsa_hmac, repo: Project.Repo
  ```
  If you wish, you may also specify the key where NcsaHmac will look for the record to authorize against:
  ```
  config :ncsa_hmac, api_keys: :some_api_key_record
  ```

  You can specify a handler function (in this case, `Helpers.handle_unauthorized`) to be called when an action is unauthorized like so:
  ```elixir
  config :ncsa_hmac, unauthorized_handler: {Helpers, :handle_unauthorized}
  ```
  or to handle when a resource is not found:
  ```elixir
  config :ncsa_hmac, not_found_handler: {Helpers, :handle_not_found}
  ```
  NcsaHmac will pass the `conn` to the handler function.
  """

  @doc """
  Load the given resource.

  Load the resource with id given by `conn.params["id"]` (or `conn.params[opts[:id_name]]` if `opts[:id_name]` is specified)
  and ecto model given by `opts[:model]` into `conn.assigns.resource_name`.

  `resource_name` is either inferred from the model name or specified in the plug declaration with the `:as` key.
  To infer the `resource_name`, the most specific(right most) name in the model's
  module name will be used, converted to underscore case.

  For example, `load_resource model: Some.Project.BlogPost` will load the resource into
  `conn.assigns.blog_post`

  If the resource cannot be fetched, `conn.assigns.resource_name` is set
  to nil.

  Required opts:

  * `:model` - Specifies the module name of the model to load resources from

  Optional opts:

  * `:as` - Specifies the `resource_name` to use
  * `:only` - Specifies which actions to authorize
  * `:except` - Specifies which actions for which to skip authorization
  * `:preload` - Specifies association(s) to preload
  * `:id_name` - Specifies the name of the id in `conn.params`, defaults to "id"
  * `:id_field` - Specifies the name of the ID field in the database for searching :id_name value, defaults to "id".
  * `:persisted` - Specifies the resource should always be loaded from the database, defaults to false
  * `:not_found_handler` - Specify a handler function to be called if the resource is not found

  Examples:
  ```
  plug :load_resource, model: Post

  plug :load_resource, model: User, preload: :posts, as: :the_user

  plug :load_resource, model: User, only: [:index, :show], preload: :posts, as: :person

  plug :load_resource, model: User, except: [:destroy]

  plug :load_resource, model: Post, id_name: "post_id", only: [:new, :create], persisted: true

  plug :load_resource, model: Post, id_name: "slug", id_field: "slug", only: [:show], persisted: true
  ```
  """
  def load_resource(conn, opts) do
    conn
    |> action_valid?(opts)
    |> case do
      true  -> _load_resource(conn, opts) |> handle_not_found(opts)
      false -> conn
    end
  end

  defp _load_resource(conn, opts) do
    get_action(conn)
    loaded_resource = fetch_resource(conn, opts)

    %{conn | assigns: Map.put(conn.assigns, resource_name(opts), loaded_resource)}
  end

  @doc """
  Authorize the resource, assuming the matching db record is loaded into the conn.

  In order to use this function,

    1) `conn.assigns[Application.get_env(:ncsa_hmac, :record, :record)]` must be an ecto
    struct representing the a record that has the signing_key and auth_id

    2) `conn.private` must be a map (this should not be a problem unless you explicitly modified it)

  If authorization succeeds, sets `conn.assigns.authorized` to true.

  After authorization, conn.assigns.resource_name is set to nil.

  Required opts:

  * `:model` - Specifies the module name of the model to authorize access to

  Optional opts:

  * `:only` - Specifies which actions to authorize
  * `:except` - Specifies which actions for which to skip authorization
  * `:preload` - Specifies association(s) to preload
  * `:id_name` - Specifies the name of the id in `conn.params`, defaults to "id"
  * `:id_field` - Specifies the name of the ID field in the database for searching :id_name value, defaults to "id".
  * `:persisted` - Specifies the resource should always be loaded from the database, defaults to false
  * `:unauthorized_handler` - Specify a handler function to be called if the action is unauthorized

  Examples:
  ```
  plug :authorize_resource, model: Post

  plug :authorize_resource, model: User, preload: :posts

  plug :authorize_resource, model: User, only: [:index, :show], preload: :posts

  plug :load_resource, model: Post, id_name: "post_id", only: [:index], persisted: true, preload: :comments

  plug :load_resource, model: Post, id_name: "slug", id_field: "slug", only: [:show], persisted: true
  ```
  """
  def authorize_resource(conn, opts) do
    conn
    |> action_valid?(opts)
    |> case do
      true  -> auth = _authorize_resource(conn, opts) |> handle_unauthorized(opts)
      false -> conn
    end
  end

  defp _authorize_resource(conn, opts) do
    authentication = NcsaHmac.Authentication.authenticate!(conn, opts)
    case authentication do
      {:ok, true}  ->
        Plug.Conn.assign(conn, :authorized, true)
          |> purge_resource(opts)
      {:error, message} ->
        Plug.Conn.assign(conn, :authorized, false)
          |> Plug.Conn.assign(:error_message, message)
          |> purge_resource(opts)
    end
  end


  @doc """
  Authorize the given resource and then load it if
  authorization succeeds.

  If the resource cannot be loaded or authorization
  fails, conn.assigns.resource_name is set to nil.

  The result of the authorization (true/false) is
  assigned to conn.assigns.authorized.

  After authorization, conn.assigns.resource_name is set to nil.

  Also, see the documentation for load_resource/2 and
  authorize_resource/2.

  Required opts:

  * `:model` - Specifies the module name of the model to load resources from

  Optional opts:

  * `:as` - Specifies the `resource_name` to use
  * `:only` - Specifies which actions to authorize
  * `:except` - Specifies which actions for which to skip authorization
  * `:preload` - Specifies association(s) to preload
  * `:id_name` - Specifies the name of the id in `conn.params`, defaults to "id"
  * `:id_field` - Specifies the name of the ID field in the database for searching :id_name value, defaults to "id".
  * `:unauthorized_handler` - Specify a handler function to be called if the action is unauthorized
  * `:not_found_handler` - Specify a handler function to be called if the resource is not found

  Note: If both an `:unauthorized_handler` and a `:not_found_handler` are specified for `load_and_authorize_resource`,
  and the request meets the criteria for both, the `:unauthorized_handler` will be called first.

  Examples:
  ```
  plug :load_and_authorize_resource, model: Post

  plug :load_and_authorize_resource, model: User, preload: :posts, as: :the_user

  plug :load_and_authorize_resource, model: User, only: [:index, :show], preload: :posts, as: :person

  plug :load_and_authorize_resource, model: User, except: [:destroy]

  plug :load_and_authorize_resource, model: Post, id_name: "slug", id_field: "slug", only: [:show], persisted: true
  ```
  """
  def load_and_authorize_resource(conn, opts) do
    conn
    |> action_valid?(opts)
    |> case do
      true  -> _load_authorize_and_purge_resource(conn, opts)
      false -> conn
    end
  end

  defp _load_authorize_and_purge_resource(conn, opts) do
    conn
    |> load_resource(opts)
    |> authorize_resource(opts)
    |> purge_resource(opts)
  end

  defp purge_resource(conn, opts),
    do: %{conn | assigns: Map.put(conn.assigns, resource_name(opts), nil)}

  defp fetch_resource(conn, opts) do
    repo = Application.get_env(:ncsa_hmac, :repo)

    field_name = (opts[:id_field] || "id")

    get_map_args = %{field_name => get_resource_id(conn, opts)}
    get_map_args = (for {key, val} <- get_map_args, into: %{}, do: {String.to_atom(key), val})

    conn.assigns
    |> Map.fetch(resource_name(opts)) # check if a resource is already loaded at the key
    |> case do
      :error ->
        repo.get_by(opts[:model], get_map_args)
      {:ok, nil} ->
        repo.get_by(opts[:model], get_map_args)
      {:ok, resource} ->
        case (resource.__struct__ == opts[:model]) do
          true  -> # A resource of the type passed as opts[:model] is already loaded; do not clobber it
            resource
          false ->
            repo.get_by(opts[:model], get_map_args)
        end
    end
  end

  defp get_resource_id(conn, opts) do
    case opts[:id_name] do
      nil ->
        conn.params["id"]
      id_name ->
        conn.params[id_name] || "THIS_SHOULD_FAIL"
    end
  end

  defp get_action(conn) do
    conn.assigns
    |> Map.fetch(:ncsa_hmac_action)
    |> case do
      {:ok, action} -> action
      _             -> conn.private.phoenix_action
    end
  end

  defp action_exempt?(conn, opts) do
    action = get_action(conn)

    (is_list(opts[:except]) && action in opts[:except])
    |> case do
      true  -> true
      false -> action == opts[:except]
    end
  end

  defp action_included?(conn, opts) do
    action = get_action(conn)

    (is_list(opts[:only]) && action in opts[:only])
    |> case do
      true  -> true
      false -> action == opts[:only]
    end
  end

  defp action_valid?(conn, opts) do
    cond do
      has_key?(opts, :except) && has_key?(opts, :only) ->
        false
      has_key?(opts, :except) ->
        !action_exempt?(conn, opts)
      has_key?(opts, :only) ->
        action_included?(conn, opts)
      true ->
        true
    end
  end

  def resource_name(opts) do
    case opts[:as] do
      nil ->
        opts[:model]
        |> Module.split
        |> List.last
        |> Macro.underscore
        |> String.to_atom
      as -> as
    end
  end

  defp handle_unauthorized(conn = %{assigns: %{authorized: true}}, _opts),
    do: conn
  defp handle_unauthorized(conn = %{assigns: %{authorized: false}}, opts),
    do: apply_error_handler(conn, :unauthorized_handler, opts)

  defp handle_not_found(conn, opts) do
    action = get_action(conn)

    case is_nil(Map.get(conn.assigns, resource_name(opts)))
      and not action in [:index, :new, :create] do

      true -> apply_error_handler(conn, :not_found_handler, opts)
      false -> conn
    end
  end

  defp apply_error_handler(conn, handler_key, opts) do
    handler = Keyword.get(opts, handler_key)
      || Application.get_env(:ncsa_hmac, handler_key)

    case handler do
      {mod, fun} -> apply(mod, fun, [conn])
      nil        -> conn
    end
  end

end
