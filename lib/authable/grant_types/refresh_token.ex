defmodule Authable.GrantType.RefreshToken do
  @moduledoc """
  RefreshToken grant type for OAuth2 Authorization Server
  """

  import Authable.GrantType.Base

  @behaviour Authable.GrantType
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
  `Authable.Model.Token` struct, otherwise `{:error, Map, :http_status_code}`.

  ## Examples

      Authable.GrantType.RefreshToken.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "refresh_token" => "XJaVz3lCFC9IfifBriA-dw",
        "scope" => "read"
      %})

        Authable.GrantType.RefreshToken.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "refresh_token" => "XJaVz3lCFC9IfifBriA-dw"
      %})
  """
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret, "refresh_token" => refresh_token, "scope" => scopes}) do
    token = @repo.get_by(@token_store, value: refresh_token)
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    create_tokens(token, client, scopes)
  end

  def authorize(%{"client_id" => client_id, "client_secret" => client_secret, "refresh_token" => refresh_token}) do
    token = @repo.get_by(@token_store, value: refresh_token)
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    create_tokens(token, client,
      (if token, do: token.details["scope"], else: ""))
  end

  def authorize(_), do: {:error,
    %{invalid_request: "Request must include at least client_id, client_secret and refresh_token parameters."},
    :bad_request}

  defp create_tokens(nil, _, _), do:
    {:error, %{invalid_token: "Token not found."}, :unauthorized}
  defp create_tokens(token, client, required_scopes) do
    {:ok, token}
    |> validate_client_match(client)
    |> validate_app_authorization
    |> validate_token_expiration
    |> validate_token_scope(required_scopes)
    |> delete_token
    |> create_oauth2_tokens(required_scopes)
  end

  defp create_oauth2_tokens({:error, err, code}, _), do: {:error, err, code}
  defp create_oauth2_tokens({:ok, token}, required_scopes) do
    create_oauth2_tokens(
      token.user_id, grant_type, token.details["client_id"],
      required_scopes, token.details["redirect_uri"])
  end

  defp delete_token({:error, err, code}), do: {:error, err, code}
  defp delete_token({:ok, token}) do
    @repo.delete!(token)
    {:ok, token}
  end

  defp validate_token_scope({:error, err, code}, _), do: {:error, err, code}
  defp validate_token_scope({:ok, token}, ""), do: {:ok, token}
  defp validate_token_scope({:ok, token}, required_scopes) do
    required_scopes = required_scopes |> Authable.Utils.String.comma_split
    scopes = Authable.Utils.String.comma_split(token.details["scope"])
    if Enum.find(required_scopes, fn(required_scope) ->
        Enum.member?(scopes, required_scope) == false end) do
      {:error, %{invalid_scope:
        "Allowed scopes for the token are #{Enum.join(scopes, ", ")}."},
        :bad_request}
    else
      {:ok, token}
    end
  end

  defp validate_token_expiration({:error, err, code}), do: {:error, err, code}
  defp validate_token_expiration({:ok, token}) do
    if @token_store.is_expired?(token) do
      {:error, %{invalid_token: "Token expired."}, :unauthorized}
    else
      {:ok, token}
    end
  end

  defp validate_app_authorization({:error, err, code}), do: {:error, err,
    code}
  defp validate_app_authorization({:ok, token}) do
    if app_authorized?(token.user_id, token.details["client_id"]) do
      {:ok, token}
    else
      {:error, %{access_revoke: "Resource owner revoked access for client."},
        :unauthorized}
    end
  end

  defp validate_client_match({:error, err, code}), do: {:error, err, code}
  defp validate_client_match({:ok, _}, nil), do:
   {:error, %{invalid_client: "Client not found."}, :unauthorized}
  defp validate_client_match({:ok, token}, client) do
    if token.details["client_id"] != client.id do
      {:error, %{invalid_grant: "Token not found."}, :unauthorized}
    else
      {:ok, token}
    end
  end

  defp grant_type, do: "refresh_token"
end
