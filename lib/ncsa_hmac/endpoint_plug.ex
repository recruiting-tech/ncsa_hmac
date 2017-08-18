defmodule NcsaHmac.EndpointPlug do
  import Plug.Conn

  @moduledoc """
  The EndpointPlug module provides functions to authenticate a web request at the Endpoint level.
  This allows the user to removal all auth configuration from the Controller level.
  """

  @doc """
  Set default opts values.
  """
  def init(opts) do
    %{id_name: "auth_id", id_field: "auth_id", key_field: "signing_key"}
    |> Map.merge(opts)
  end

  @doc """
  Comply with the module plug standard. Take a conn and optional map (opts) as arguments.
  The :mount list is configured in the endpoint. Will match the beginning of the
  request path up to the mount list. This will greedily match all methods and routes
  with additional path parameters. If the conn.path_info list does not match the opts:mount
  list, the conn will be returned to the endpoint for further processing.
  TODO: upgrade to elixir 1.5 and use the @impl annotation
  """
  def call(conn, opts) do
    case match_mount?(conn, opts) do
      true -> authorize_resource(conn, opts)
      false -> conn
    end
  end

  @doc """
  :preprocess_conn will set the raw request body into :private.raw_body on the conn.
  :assign_resource_id will set the auth_id into :private at the opts[:field_name] key.
  :load_resource will query the approriate model and repo based on opts values.
  :authorize_request will validate the request authorization key againt the request
  details. See NcsaHmac.Canonical for specifics.
  :purge_resource will set the :assigns.authorized value and remove the model from
  the conn request struct.
  """
  def authorize_resource(conn, opts) do
    try do
      conn
      |> preprocess_conn(opts)
      |> assign_resource_id(opts)
      |> load_resource(opts)
      |> authorize_request(opts)
      |> purge_resource(opts)
    rescue
      e in NcsaHmac.AuthorizationError -> handle_unauthorized(conn, e.message, opts)
    end
  end

  defp load_resource(conn, opts) do
    loaded_resource = fetch_resource(conn, opts)

    %{conn | assigns: Map.put(conn.assigns, resource_name(opts), loaded_resource)}
  end

  defp authorize_request(conn, opts) do
    authentication = NcsaHmac.Authentication.authenticate!(conn, opts)
    case authentication do
      {:ok, true}  ->
        conn
        |> Plug.Conn.assign(:authorized, true)
        |> purge_resource(opts)
      {:error, message} ->
        handle_unauthorized(conn, message, opts)
    end
  end

  defp preprocess_conn(conn, _opts) do
    {status, body, _} = Plug.Conn.read_body(conn)
    case status do
      :ok -> conn |> Plug.Conn.put_private(:raw_body, body)
      _ -> conn
    end
  end

  defp purge_resource(conn, opts) do
    %{conn | assigns: Map.put(conn.assigns, resource_name(opts), nil)}
  end

  defp fetch_resource(conn, opts) do
    repo = opts[:repo] || Application.get_env(:ncsa_hmac, :repo)
    map_args = get_resource_args(conn, opts)
    conn.assigns
    |> Map.fetch(resource_name(opts)) # check if a resource is already loaded at the key
    |> case do
      :error ->
        repo.get_by(opts[:model], map_args)
      {:ok, nil} ->
        repo.get_by(opts[:model], map_args)
      {:ok, resource} ->
        case (resource.__struct__ == opts[:model]) do
          true  -> # A resource of the type passed as opts[:model] is already loaded; do not clobber it
            resource
          false ->
            repo.get_by(opts[:model], map_args)
        end
    end
  end

  defp assign_resource_id(conn, opts) do
    field_name = field_name(opts)
    Plug.Conn.put_private(conn, field_name, get_resource_args(conn, opts)[field_name])
  end

  defp field_name(opts) do
    String.to_atom(opts[:id_field] || "id")
  end

  defp get_resource_args(conn, opts) do
    resource_id = NcsaHmac.Authentication.auth_id(conn)
    resource = case resource_id do
      nil -> get_resource_id(conn, opts)
      _ -> resource_id
    end
    %{field_name(opts) => resource}
  end

  defp get_resource_id(conn, opts) do
    case opts[:id_name] do
      nil ->
        conn.params["id"]
      id_name ->
        conn.params[id_name]
    end
  end

  defp resource_name(opts) do
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

  defp handle_unauthorized(conn, message, opts) do
    conn
    |> purge_resource(opts)
    |> assign(:authorized, false)
    |> assign(:error_message, message)
    |> put_resp_content_type("application/json")
    |> send_resp(401, error_json(message))
    |> halt()
  end

  defp error_json(error_message) do
    JSON.encode! %{errors: [%{message: "Unauthorized", detail: error_message}]}
  end

  defp match_mount?(conn, opts) do
    path = conn.path_info
    mount = Dict.get(opts, :mount)
    mount == Enum.slice(path, 0, Enum.count(mount))
  end
end
