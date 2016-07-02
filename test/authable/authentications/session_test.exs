defmodule Authable.Authentication.SessionTest do
  use ExUnit.Case
  use Authable.Rollbackable
  use Authable.RepoCase
  import Authable.Factory
  alias Authable.Authentication.Session, as: SessionAuthentication

  @session_token_value "session_token_1234"

  setup do
    user = insert(:user)
    insert(:session_token, %{value: @session_token_value, user: user})
    :ok
  end

  test "authorize with session auth token" do
    {:ok, authorized_user} = SessionAuthentication.authenticate(
      @session_token_value, [])
    refute is_nil(authorized_user)
  end
end
