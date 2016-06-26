defmodule Authable.GrantTypes.Password do
  @moduledoc """
  Password grant type for OAuth2 Authorization Server
  """

  import Authable.GrantTypes.Base
  alias Authable.Utils.Crypt, as: CryptUtil

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @client Application.get_env(:authable, :client)


  @doc """
  Authorize client for 'resouce owner' using resouce owner credentials and
  client identifier.

  For authorization, authorize function requires a map contains 'email' and
  'password', 'scope' and 'client_id'. With valid credentials;
  it automatically creates access_token and
  refresh_token(if enabled via config) then it returns
  access_token struct, otherwise nil.

  ## Examples

      Authable.GrantTypes.Password.authorize(%{
        "email" => "foo@example.com",
        "password" => "12345678",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "scope" => "read"
      %})
  """
  def authorize(%{"email" => email, "password" => password, "client_id" => client_id, "scope" => scope}) do
    client = @repo.get(@client, client_id)
    user = @repo.get_by(@resource_owner, email: email)
    if client && user && match_with_user_password(password, user) do
      create_oauth2_tokens(user, grant_type, client_id, scope)
    end
  end

  defp grant_type, do: "password"

  defp match_with_user_password(password, user) do
    CryptUtil.match_password(password, Map.get(user, :password, ""))
  end
end
