defmodule Authable.Authentications.Token do
  @moduledoc """
  Base token authentication helper. Differently from Bearer or Session, this
  module is a generic helper module. It enables to match with any token type
  from 'token store(Authable.Token)'.
  """

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @token_store Application.get_env(:authable, :token_store)

  @doc """
  Authenticates resource-owner using given token name and value pairs.

  It matches resource owner with given token name and value.
  If any resource owner matched given credentials,
  it returns resource owner struct, otherwise nil.

  ## Examples

      # Suppose we store a confirmation_token at 'token store'
      # with token value "ct123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentications.Token.authenticate("confirmation_token",
        "ct123456789")
  """
  def authenticate(token_name, token_value) do
    token = @repo.get_by(@token_store, value: token_value, name: token_name)
    if token && !@token_store.is_expired?(token) do
      @repo.get(@resource_owner, token.user_id)
    end
  end
end
