defmodule Authable.Authentications.Basic do
  @moduledoc """
  Basic authentication helper module
  """

  alias Authable.Utils.Crypt, as: CryptUtil

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)

  @doc """
  Authenticates resource-owner using Basic Authentication header value.

  It handles the decoding the 'Authorization: Basic {auth_credentials}'
  and matches resource owner with given email and password. If any resource
  owner matched given credentials, it returns resource owner struct,
  otherwise nil.

  ## Examples

      # Suppose we have a resource owner with
      # email: foo@example.com and password: 12345678.
      # Base 64 encoding of email:password combination will be
      # 'Zm9vQGV4YW1wbGUuY29tOjEyMzQ1Njc4'. If we pass the encoded value
      # to the function, it will return resource-owner
      Authable.Authentications.Basic.authenticate(
        "Zm9vQGV4YW1wbGUuY29tOjEyMzQ1Njc4")
  """
  def authenticate(auth_credentials) do
    case Base.decode64(auth_credentials) do
      {:ok, credentials} ->
        [email, password] = String.split(credentials, ":")
        authenticate(email, password)
      :error -> nil
    end
  end

  defp authenticate(email, password) do
    user = @repo.get_by(@resource_owner, email: email)
    if user && match_with_user_password(password, user), do: user
  end

  defp match_with_user_password(password, user) do
    CryptUtil.match_password(password, Map.get(user, :password, ""))
  end
end
