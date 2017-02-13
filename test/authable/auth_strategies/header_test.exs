defmodule Authable.AuthStrategy.HeaderTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.ModelCase
  use Authable.ConnCase
  import Authable.Factory
  alias Authable.AuthStrategy.Header, as: HeaderAuthStrategy

  setup do
    {:ok, conn: Authable.ConnTest.build_conn()}
  end

  test "returns user model when authenticates with Basic Authentication using valid data", %{conn: conn} do
    user = insert(:user)
    basic_auth_token = Base.encode64("#{user.email}:12345678")
    conn = conn |> put_req_header("authorization", "Basic #{basic_auth_token}")
    assert {:ok, user} == HeaderAuthStrategy.authenticate(conn, ~w(read))
  end

  test "returns user model and token when authenticates with Bearer Authentication using valid data", %{conn: conn} do
    user = insert(:user)
    client = insert(:client, user: user)
    token = insert(:access_token, user: user, details: %{client_id: client.id, scope: "read"})
    conn = conn |> put_req_header("authorization", "Bearer #{token.value}")
    {:ok, authorized_user, current_token} = HeaderAuthStrategy.authenticate(conn, ~w(read))
    assert authorized_user == user
    assert current_token.id == token.id
  end

  test "returns user model and token when authenticates with X-API-TOKEN using valid data", %{conn: conn} do
    user = insert(:user)
    client = insert(:client, user: user)
    token = insert(:access_token, user: user, details: %{client_id: client.id, scope: "read"})
    conn = conn |> put_req_header("x-api-token", "#{token.value}")
    {:ok, authorized_user, current_token} = HeaderAuthStrategy.authenticate(conn, ~w(read))
    assert authorized_user == user
    assert current_token.id == token.id
  end

  # applies for Basic, Berarer and any others...
  test "returns nil when no header matches", %{conn: conn} do
    assert is_nil(HeaderAuthStrategy.authenticate(conn, []))
  end
end
