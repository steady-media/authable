defmodule Authable.GrantType.BaseTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.GrantType.Base, as: BaseGrantType

  @scopes "read"
  @repo Application.get_env(:authable, :repo)
  @token_store Application.get_env(:authable, :token_store)

  setup do
    resource_owner = insert(:user)
    client_owner = insert(:user)
    client = insert(:client, user_id: client_owner.id)
    insert(:app, scope: @scopes, user_id: resource_owner.id, client_id: client.id)
    insert(:authorization_code, user_id: resource_owner.id, details: %{client_id: client.id, redirect_uri: client.redirect_uri, scope: @scopes})
    params = %{"client_id" => client.id, "user_id" => resource_owner.id}
    {:ok, params: params, resource_owner: resource_owner, client: client}
  end

  test "app_authorized? with authorized app for client", %{params: params} do
    assert BaseGrantType.app_authorized? params["user_id"], params["client_id"]
  end

  test "app_authorized? with unauthorized app for client", %{params: params} do
    client = insert(:client)
    refute BaseGrantType.app_authorized? params["user_id"], client.id
  end

  test "create_oauth2_tokens inserts a refresh token when the refresh_token grant type is enabled", %{resource_owner: resource_owner, client: client} do
    BaseGrantType.create_oauth2_tokens(resource_owner.id, "authorization_code", client.id, "read")
    assert @repo.get_by(@token_store, name: "refresh_token") != nil
  end
end
