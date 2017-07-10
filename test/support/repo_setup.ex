defmodule User do
  defstruct id: 1
end

defmodule ApiKey do
  use Ecto.Schema

  schema "api_key" do
    field :user_id, :integer, default: 1
    field :slug, :string
    field :auth_id, :string
    field :signing_key, :string
  end
end

defmodule Repo do
  def get(ApiKey, 1), do: %ApiKey{id: 1}
  def get(ApiKey, 2), do: %ApiKey{id: 2}
  def get(ApiKey, _), do: nil
  def all(_), do: [%ApiKey{id: 1}, %ApiKey{id: 2}]
  def get_by(ApiKey, %{id: 1}), do: %ApiKey{id: 1}
  def get_by(ApiKey, %{id: 2}), do: %ApiKey{id: 2}
  def get_by(ApiKey, %{id: _}), do: nil

  def get_by(ApiKey, %{slug: "slug1"}), do: %ApiKey{id: 1, slug: "slug1"}
  def get_by(ApiKey, %{slug: "slug2"}), do: %ApiKey{id: 2, slug: "slug2"}
  def get_by(ApiKey, %{slug: _}), do: nil
  def get_by(ApiKey, %{auth_id: "auth_id1"}), do: %ApiKey{id: 1, auth_id: "auth_id1"}
  def get_by(ApiKey, %{auth_id: "auth_id2"}), do: %ApiKey{id: 2, auth_id: "auth_id2"}
  def get_by(ApiKey, %{auth_id: "auth_id_valid"}), do: %ApiKey{id: 11, auth_id: "auth_id_valid", signing_key: "signing_key"}
  def get_by(ApiKey, %{auth_id: _}), do: nil
end
