defmodule Authable.Authentications.Session do
  @moduledoc """
  Bearer authencation helper module
  """

  alias Authable.Authentications.Token, as: TokenAuthentication

  @doc """
  Authenticates resource-owner using session_token token value.

  It matches resource owner with given session_token. If any resource owner
  matched given credentials, it returns resource owner struct, otherwise nil.

  ## Examples

      # Suppose we have a session_token at 'token store(Authable.Token)'
      # with token value "st123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentications.Session.authenticate("st123456789")
  """
  def authenticate(session_token) do
    TokenAuthentication.authenticate("session_token", session_token)
  end
end
