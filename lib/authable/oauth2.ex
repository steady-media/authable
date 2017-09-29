defmodule Authable.OAuth2 do
  @moduledoc """
  OAuth2 authorization strategy router
  """

  import Ecto.Query, only: [from: 2]

  @repo Application.get_env(:authable, :repo)
  @token_store Application.get_env(:authable, :token_store)
  @client Application.get_env(:authable, :client)
  @app Application.get_env(:authable, :app)
  @grant_types Application.get_env(:authable, :grant_types)
  @scopes Application.get_env(:authable, :scopes)

  @doc """
  Calls appropriate module authorize function for given grant type.

  It simply authorizes based on allowed grant types in configuration and then
  returns access token as @token_store(Authable.Model.Token) model.

  ## Examples

      # For authorization_code grant type
      Authable.OAuth2.authorize(%{
        "grant_type" => "authorization_code",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "redirect_uri" => "http://localhost:4000/oauth2/callbacks",
        "code" => "W_hb8JEDmeYChsNfOGCmbQ"
      %})

      # For client_credentials grant type
      Authable.OAuth2.authorize(%{
        "grant_type" => "client_credentials",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q"
      %})

      # For password grant type
      Authable.OAuth2.authorize(%{
        "grant_type" => "password",
        "email" => "foo@example.com",
        "password" => "12345678",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "scope" => "read"
      %})

      # For refresh_token grant type
      Authable.OAuth2.authorize(%{
        "grant_type" => "refresh_token",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "refresh_token" => "XJaVz3lCFC9IfifBriA-dw"
      %})

      # For any other grant type; must implement authorize function and returns
      # access_token as @token_store(Authable.Model.Token) model.
  """
  def authorize(params) do
    strategy_check(params["grant_type"])
    @grant_types[String.to_existing_atom(params["grant_type"])].authorize(params)
  end

  @doc """
  Authorizes client for resouce owner with given scopes

  It authorizes app to access resouce owner's resouces. Simply, user
  authorizes a client to grant resouces with scopes. If client already
  authorized for resouce owner then it checks scopes and updates when necessary.

  ## Examples

      # For authorization_code grant type
      Authable.OAuth2.authorize_app(user, %{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "redirect_uri" => "http://localhost:4000/oauth2/callbacks",
        "scope" => "read,write"
      %})
  """
  def authorize_app(user, %{"client_id" => client_id, "redirect_uri" => redirect_uri, "scope" => scope}) do
    client = @repo.get_by(@client, id: client_id, redirect_uri: redirect_uri)
    authorize_app(user, client, scope)
  end

  defp authorize_app(_, nil, _), do: {:error,
   %{invalid_client: "Client not found"}, :unprocessable_entity}
  defp authorize_app(user, client, scope) do
    app = @repo.get_by(@app, user_id: user.id, client_id: client.id)
    authorize_app(user, client, app, scope)
  end
  defp authorize_app(user, client, nil, scope) do
    @repo.insert!(@app.changeset(%@app{}, %{
      user_id: user.id,
      client_id: client.id,
      scope: scope
    }))
  end
  defp authorize_app(_, _, app, scope) do
    if app.scope != scope do
      scope = scope
      |> Authable.Utils.String.comma_split
      |> Enum.concat(Authable.Utils.String.comma_split(app.scope))
      |> Enum.uniq()
      scope = @scopes -- (@scopes -- scope)
      @repo.update!(@app.changeset(app, %{scope: Enum.join(scope, ",")}))
    else
      app
    end
  end

  @doc """
  Revokes access to resouce owner's resources.

  Delete all tokens and then removes app for given app identifier.

  ## Examples

      # For revoking client(uninstall app)
      Authable.OAuth2.revoke_app_authorization(user, %{
        "id" => "12024ca6-192b-469d-bfb6-9b45023ad13e"
      %})
  """
  def revoke_app_authorization(user, %{"id" => id}) do
    app = @repo.get_by!(@app, id: id, user_id: user.id)
    @repo.delete!(app)

    query = (from t in @token_store, where: t.user_id == ^app.user_id and
      fragment("?->>'client_id' = ?", t.details, ^app.client_id))
    @repo.delete_all(query)
  end

  defp strategy_check(grant_type) do
    unless Map.has_key?(@grant_types, String.to_existing_atom(grant_type)) do
      raise Authable.Error.SuspiciousActivity,
        message: "Strategy for '#{grant_type}' is not enabled!"
    end
  end
end
