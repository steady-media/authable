defmodule Authable.Authentication.BaseTest do
  use ExUnit.Case
  alias Authable.Authentication.Base, as: BaseAuthentication

  test "required scopes are satisfied" do
    required_scopes = ["read"]
    assert BaseAuthentication.is_authorized?(required_scopes, "read") ==
      {:ok, true}
  end

  test "required scopes are not satisfied" do
    required_scopes = ["read", "write"]
    assert BaseAuthentication.is_authorized?(required_scopes, "read") ==
      {:error, %{insufficient_scope: "Required scopes are read, write."}}
  end
end
