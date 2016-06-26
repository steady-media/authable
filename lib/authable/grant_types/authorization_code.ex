defmodule Authable.GrantTypes.AuthorizationCode do
  @moduledoc """
  AuthorizationCode grant type for OAuth2 Authorization Server
  """

  import Authable.GrantTypes.Base

  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @token_store Application.get_env(:authable, :token_store)
  @client Application.get_env(:authable, :client)
  @app Application.get_env(:authable, :app)

  @doc """
  Authorize client for 'resource owner' using client credentials and
  authorization code.

  For authorization, authorize function requires a map contains 'client_id',
  'client_secret', 'redirect_uri'(must match with authorization code token's),
  and 'code' keys. With valid credentials; it automatically creates
  access_token and refresh_token(if enabled via config) then it returns
  access_token struct, otherwise nil.

  ## Examples

      Authable.GrantTypes.AuthorizationCode.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "redirect_uri" => "http://localhost:4000/oauth2/callbacks",
        "code" => "W_hb8JEDmeYChsNfOGCmbQ"
      %})
  """
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret, "code" => code, "redirect_uri" => redirect_uri}) do
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    if client, do: authorize(code, redirect_uri, client.id), else: nil
  end

  defp authorize(code, redirect_uri, client_id) do
    token = @repo.get_by(@token_store, value: code)
    if token && !@token_store.is_expired?(token) &&
       token.details["redirect_uri"] == redirect_uri &&
       token.details["client_id"] == client_id do
      user = @repo.get(@resource_owner, token.user_id)
      if user && app_authorized?(user.id, client_id) do
        @repo.delete!(token)
        create_oauth2_tokens(user, grant_type, client_id,
          token.details["scope"], redirect_uri)
      end
    end
  end

  defp grant_type, do: "authorization_code"
end
