defmodule Authable.GrantTypes.RefreshToken do
  @moduledoc """
  RefreshToken grant type for OAuth2 Authorization Server
  """

  import Authable.GrantTypes.Base

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @token_store Application.get_env(:authable, :token_store)
  @client Application.get_env(:authable, :client)
  @app Application.get_env(:authable, :app)

  @doc """
  Authorize client for 'resouce owner' using client credentials and
  refresh token.

  For authorization, authorize function requires a map contains 'client_id' and
  'client_secret' and 'refresh_token'. With valid credentials;
  it automatically creates access_token and
  refresh_token(if enabled via config) then it returns
  access_token struct, otherwise nil.

  ## Examples

      Authable.GrantTypes.RefreshToken.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "refresh_token" => "XJaVz3lCFC9IfifBriA-dw"
      %})
  """
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret, "refresh_token" => refresh_token}) do
    token = @repo.get_by(@token_store, value: refresh_token)
    if token && !@token_store.is_expired?(token) &&
       token.details["client_id"] == client_id do
      client = @repo.get_by(@client, id: client_id, secret: client_secret)
      user = @repo.get(@resource_owner, token.user_id)
      if client && user && app_authorized?(user.id, client.id) do
        access_token = create_oauth2_tokens(user, grant_type, client_id,
          token.details["scope"])
        @repo.delete!(token)
        access_token
      end
    end
  end

  defp grant_type, do: "refresh_token"


end
