# NcsaHmac

This is an elixir implementation of HMAC SHA request signing that takes fair amount of influence from the ey-hmac gem:
https://github.com/engineyard/hmac

This is not a direct port of the Engine Yard gem, but it follows many of the same implementation choices and uses the same request canonicalization methodology.

Important Elixir reference points for this project were erlang-hmac-sha:
https://github.com/hypernumbers/erlang-hmac-sha
and canary:
https://github.com/cpjk/canary

In particular, the canary package was excellent guidance for how to inject the
Repo as a dependency of the project and make testing possible.

## Usage

This plug supports several use cases. It can both be the original signer of the details of a request, or it can validate incoming requests.

When used to validate, incoming requests there a 2 ways to mount the plug, in the controller directly matching the auth to any or all controller functions, or in the endpoint.ex module matching to the request path.

### Controller Authentication

  To use the Plug at the Controller level, import the plug and plug the :load_and_authorize_resource function for the routes you want to authenticate.

  ```
  import NcsaHmac.Plug
  plug :load_and_authorize_resource, model: MyApplication.MyApiKeyModelName, id_name: "auth_id", id_field: "auth_id", key_field: "signing_key" repo: MyApplication.Repo, only: :the_authenticated_function
  ```

  The fields: :id_name, :id_field, and :key_field are optional, if not provided the gem will use default values. The :repo field is also optional, although the Repo must be specified in the controller, or the application config.

    - :id_name and :id_field default to :id.

    - :key_field defaults to :signing_key.

  The final argument is an optional matcher for the functions which you wish to authenticate, uses phoenix matchers.

    - only: [:actions]

    - when action in [:actions]

    - when not action in [:actions]

### Endpoint Authentication

  You can also enable authentication higher up the request stack in the application endpoint. To confiugure authentication at the endpoint level, add the following to endpoint.ex:

  ```
  plug NcsaHmac.EndpointPlug, %{
    mount: ["api", "authenticated", "route", "path"],
    model: MyApplication.MyApiKeyModelName,
    repo: MyApplication.Repo
  }
  ```

  The :mount field defines the path for comparison to the Plug.Conn :path_info field. :mount will match on the entire :mount list and will ignore and additional path values. For example, if mount is defined as ["a", "b"], with will match and authenticate any of the following paths:

    - "/a/b"
    - "/a/b?who=ami"
    - "/a/b/c"
    - "/a/b/c/d"

  The authentication matching also does not look at the HTTP method, so GET, POST, PUT, DELETE, etc verbs will all get authenticated.

  The :model field defines the the Repo Model name where the API keys are stored.

  The :repo field is optional, although the Repo must be specified in the controller, or the application config.

### Repo Configuration

  * *To configure the Repo in Application config:*

  ```
  # Configure NcsaHmac in config.exs or prod.exs as appropriate.
  config :ncsa_hmac, repo: MyApplication.Repo
  ```

  * *To configure the Repo in opts:*

  add a key and value to the opts config in the controller or endpoint, as appropriate.

  `repo: MyApplication.Repo`

### Tests

  The package has been tested against Elixir versions 1.3.X, 1.4.5, and 1.5.1.
  It is known to work in production against Elixir version 1.3.X.

  If yoy find any issues, please

## Installation

The package can be installed as:

  1. Add git: `ncsa_hmac` to your list of dependencies in `mix.exs`:

    ```
    def deps do
      [{:ncsa_hmac, git: "git@github.com:NCSAAthleticRecruiting/ncsa_hmac.git"}]
    end
    ```

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add the published `ncsa_hmac` to your list of dependencies in `mix.exs`:

    ```
    def deps do
      [{:ncsa_hmac, "~> 0.8.0"}]
    end
    ```

  2. Ensure `ncsa_hmac` is started before your application:

    ```
    def application do
      [applications: [:ncsa_hmac]]
    end
    ```

