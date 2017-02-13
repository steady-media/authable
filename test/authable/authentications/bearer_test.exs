defmodule Authable.Authentication.BearerTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.Authentication.Bearer, as: BearerAuthentication

  @access_token_value "access_token_1234"

  setup do
    user = insert(:user)
    token = insert(:access_token, %{value: @access_token_value, user: user})
    {:ok, user: user, token: token}
  end

  test "authorize with bearer authentication", %{user: user, token: token} do
    {:ok, authorized_user, current_token} = BearerAuthentication.authenticate(
      @access_token_value, [])
    assert authorized_user == user
    assert current_token.id == token.id
  end

  test "authorize with bearer authentication using Bearer prefix", %{user: user, token: token} do
    {:ok, authorized_user, current_token} = BearerAuthentication.authenticate(
      "Bearer #{@access_token_value}", [])
    assert authorized_user == user
    assert current_token.id == token.id
  end

  test "authorize with bearer authentication from map parameters", %{user: user, token: token} do
    {:ok, authorized_user, current_token} = BearerAuthentication.authenticate(
      %{"access_token" => @access_token_value}, [])
    assert authorized_user == user
    assert current_token.id == token.id
  end
end
