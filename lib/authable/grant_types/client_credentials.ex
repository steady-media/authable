defmodule Authable.GrantTypes.ClientCredentials do
  @moduledoc """
  ClientCredentials grant type for OAuth2 Authorization Server
  """

  import Authable.GrantTypes.Base

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @client Application.get_env(:authable, :client)

  @doc """
  Authorize client for 'client owner' using client credentials.

  For authorization, authorize function requires a map contains 'client_id' and
  'client_secret'. With valid credentials; it automatically creates
  access_token and refresh_token(if enabled via config) then it returns
  access_token struct, otherwise nil.

  ## Examples

      Authable.GrantTypes.ClientCredentials.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q"
      %})
  """
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret}) do
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    user = @repo.get(@resource_owner, client.user_id)
    if client && user do
      scopes = Enum.join(Application.get_env(:authable, :scopes), ",")
      create_oauth2_tokens(user, grant_type, client_id, scopes)
    end
  end

  defp grant_type, do: "client_credentials"
end
