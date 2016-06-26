defmodule Authable.Authentications.Bearer do
  @moduledoc """
  Bearer authencation helper module
  """

  alias Authable.Authentications.Token, as: TokenAuthentication

  @doc """
  Authenticates resource-owner using access_token map.

  It reads access_token value from given input and delegates value to
  Authable.Authentications.Bearer.authenticate/1 function.

  ## Examples

      # Suppose we have a access_token at 'token store(Authable.Token)'
      # with token value "at123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentications.Bearer.authenticate(
       %{"access_token" => "at123456789"})
  """
  def authenticate(%{"access_token" => access_token}) do
    authenticate(access_token)
  end

  @doc """
  Authenticates resource-owner using access_token token value.

  It matches resource owner with given access_token. If any resource owner
  matched given credentials, it returns resource owner struct, otherwise nil.

  ## Examples

      # Suppose we have a access_token at 'token store(Authable.Token)'
      # with token value "at123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentications.Bearer.authenticate("at123456789")
  """
  def authenticate(access_token) do
    TokenAuthentication.authenticate("access_token", access_token)
  end
end
