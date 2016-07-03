defmodule Authable.Authentication.Token do
  @moduledoc """
  Base token authentication helper, implements Authable.Authentication
  behaviour. Differently from Bearer or Session, this module is a generic
  helper module. It enables to match with any token type from
  'token store(Authable.Token)'.
  """

  import Authable.Authentication.Base

  @behaviour Authable.Authentication
  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @token_store Application.get_env(:authable, :token_store)


  @doc """
  Authenticates resource-owner using given token name and value pairs.

  It matches resource owner with given token name and value.
  If any resource owner matched given credentials,
  it returns `Authable.Model.User` struct, otherwise
  `{:error, Map, :http_status_code}`.

  ## Examples

      # Suppose we store a confirmation_token at 'token store'
      # with token value "ct123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentication.Token.authenticate({"confirmation_token",
        "ct123456789"}, ["read", "write"])
  """
  def authenticate({token_name, token_value}, required_scopes) do
    token_check(
      @repo.get_by(@token_store, value: token_value, name: token_name),
      required_scopes
    )
  end

  defp token_check(nil, _), do: {:error, %{invalid_token: "Token not found."},
    :unauthorized}
  defp token_check(token, required_scopes) do
    if @token_store.is_expired?(token) do
      {:error, %{invalid_token: "Token expired."}, :unauthorized}
    else
      case is_authorized?(required_scopes, token.details["scope"]) do
        {:ok, true} ->
          resource_owner_check(
            @repo.get(@resource_owner, token.user_id)
          )
        {:error, errors} -> {:error, errors, :forbidden}
      end
    end
  end

  defp resource_owner_check(nil) do
    {:error, %{invalid_token: "User not found."}, :unauthorized}
  end

  defp resource_owner_check(resource_owner) do
    {:ok, resource_owner}
  end
end
