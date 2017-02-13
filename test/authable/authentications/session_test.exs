defmodule Authable.Authentication.SessionTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.Authentication.Session, as: SessionAuthentication

  @session_token_value "session_token_1234"

  setup do
    user = insert(:user)
    token = insert(:session_token, %{value: @session_token_value, user: user})
    {:ok, user: user, token: token}
  end

  test "authorize with session auth token", %{user: user, token: token} do
    {:ok, authorized_user, current_token} = SessionAuthentication.authenticate(
      @session_token_value, [])
    assert authorized_user == user
    assert current_token.id == token.id
  end
end
