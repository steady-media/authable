defmodule Authable.AuthStrategy.QueryParamTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.ModelCase
  use Authable.ConnCase
  import Authable.Factory
  alias Authable.AuthStrategy.QueryParam, as: QueryParamStrategy

  setup do
    {:ok, conn: Authable.ConnTest.build_conn()}
  end

  test "returns user model and token when authenticates with access_token query string using valid data", %{conn: conn} do
    user = insert(:user)
    client = insert(:client, user: user)
    token = insert(:access_token, user: user, details: %{client_id: client.id, scope: "read,write"})
    params = %{"access_token" => token.value}
    conn = conn |> fetch_query_params |> Map.put(:query_params, params)

    {:ok, authorized_user, current_token} = QueryParamStrategy.authenticate(conn, ~w(read))
    assert authorized_user == user
    assert current_token.id == token.id
  end

  test "returns :error when fails to authenticates with access_token query string using invalid data", %{conn: conn} do
    params = %{"access_token" => "invalid"}
    conn = conn |> fetch_query_params |> Map.put(:query_params, params)
    {result, _, _} = QueryParamStrategy.authenticate(conn, [])
    assert result == :error
  end

  test "returns nil when no query params matches", %{conn: conn} do
    params = %{}
    conn = conn |> fetch_query_params |> Map.put(:query_params, params)
    assert is_nil(QueryParamStrategy.authenticate(conn, []))
  end
end
