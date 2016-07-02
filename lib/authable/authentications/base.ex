defmodule Authable.Authentication.Base do
  @moduledoc """
  Base authentication helper module, includes common helper function to
  verify authentication process.
  """

  @doc """
  Checks if the required scopes included in given scopes.

  OAuth2 requires scope validation to authenticate a client for resource owner.
  To accomplish this behaviour each resource access allowence must be checked
  using scopes.

  Returns {:ok, true} or {:error, [insufficient_scope: "Required scopes..."]}

  ## Examples

      Authable.Authentication.Base.is_authorized?(
        ["read", "write"], "read")
        => {:error, [insufficient_scope:
        "Required scopes are read, write."]}

      Authable.Authentication.Base.is_authorized?(["write"], "read,write")
        => {:ok, true}
  """
  def is_authorized?(required_scopes, scopes) do
    scopes = String.split(scopes, ",", trim: true)
    if Enum.find(required_scopes, fn(required_scope) ->
        Enum.member?(scopes, required_scope) == false end) do
      {:error, %{insufficient_scope:
        "Required scopes are #{Enum.join(required_scopes, ", ")}."}}
    else
      {:ok, true}
    end
  end
end