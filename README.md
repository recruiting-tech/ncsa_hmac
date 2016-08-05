# NcsaHmac

This is an elixir implementation of HMAC SHA request signing that takes fair amount of influence from the ey-hmac gem:
https://github.com/engineyard/hmac

This is not a direct port of the Engine Yard gem, but it follows many of the same implementation choices and uses the same request canonicalization methodology.

Important Elixir reference points for this project were erlang-hmac-sha:
https://github.com/hypernumbers/erlang-hmac-sha
and canary:
https://github.com/cpjk/canary

## Installation

The package can be installed as:

  1. Add git: `ncsa_hmac` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ncsa_hmac, git: "git@github.com:NCSAAthleticRecruiting/ncsa_hmac.git"}]
    end
    ```

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Or add the published `ncsa_hmac` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ncsa_hmac, "~> 0.1.0"}]
    end
    ```

  2. Ensure `ncsa_hmac` is started before your application:

    ```elixir
    def application do
      [applications: [:ncsa_hmac]]
    end
    ```



