defmodule Authable.GrantTypes.BaseTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.GrantTypes.Base, as: BaseGrantType

  @scopes "read"

  setup do
    resource_owner = insert(:user)
    client_owner = insert(:user)
    client = insert(:client, user_id: client_owner.id)
    insert(:app, scope: @scopes, user_id: resource_owner.id, client_id: client.id)
    token = insert(:authorization_code, user_id: resource_owner.id, details: %{client_id: client.id, redirect_uri: client.redirect_uri, scope: @scopes})
    params = %{"client_id" => client.id, "user_id" => resource_owner.id}
    {:ok, [params: params]}
  end

  test "authorize implementation" do
    assert_raise Authable.NotImplementedError,
      fn -> BaseGrantType.authorize(%{}) end
  end

  test "app_authorized? with authorized app for client", %{params: params} do
    assert BaseGrantType.app_authorized? params["user_id"], params["client_id"]
  end

  test "app_authorized? with unauthorized app for client", %{params: params} do
    client = insert(:client)
    refute BaseGrantType.app_authorized? params["user_id"], client.id
  end
end
