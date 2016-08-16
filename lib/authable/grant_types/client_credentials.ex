defmodule Authable.GrantType.ClientCredentials do
  @moduledoc """
  ClientCredentials grant type for OAuth2 Authorization Server
  """

  import Authable.GrantType.Base
  alias Authable.GrantType.Error, as: GrantTypeError

  @behaviour Authable.GrantType
  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @client Application.get_env(:authable, :client)
  @scopes Enum.join(Application.get_env(:authable, :scopes), ",")

  @doc """
  Authorize client for 'client owner' using client credentials.

  For authorization, authorize function requires a map contains 'client_id' and
  'client_secret'. With valid credentials; it automatically creates
  access_token and refresh_token(if enabled via config) then it returns
  `Authable.Model.Token` struct, otherwise `{:error, Map, :http_status_code}`.

  ## Examples

      # With OAuth2 optional scope
      Authable.GrantType.ClientCredentials.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q",
        "scope" => "read"
      %})

      # Without OAuth2 optional scope
      Authable.GrantType.ClientCredentials.authorize(%{
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "client_secret" => "Wi7Y_Q5LU4iIwJArgqXq2Q"
      %})
  """
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret, "scope" => scopes}) do
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    create_tokens(client, scopes)
  end
  def authorize(%{"client_id" => client_id, "client_secret" => client_secret}) do
    client = @repo.get_by(@client, id: client_id, secret: client_secret)
    create_tokens(client, @scopes)
  end
  def authorize(_) do
    GrantTypeError.invalid_request(
      "Request must include at least client_id, client_secret parameters.")
  end

  defp create_tokens(nil, _),
    do: GrantTypeError.invalid_client("Invalid client id or secret.")
  defp create_tokens(client, scopes) do
    {:ok, client}
    |> validate_token_scope(scopes)
    |> create_oauth2_tokens(scopes)
  end

  defp create_oauth2_tokens({:error, err, code}, _),
    do: {:error, err, code}
  defp create_oauth2_tokens({:ok, client}, scopes),
    do: create_oauth2_tokens(client.user_id, grant_type, client.id, scopes)

  defp validate_token_scope({:error, err, code}, _),
    do: {:error, err, code}
  defp validate_token_scope({:ok, client}, ""),
    do: {:ok, client}
  defp validate_token_scope({:ok, client}, required_scopes) do
    scopes = Authable.Utils.String.comma_split(@scopes)
    required_scopes = Authable.Utils.String.comma_split(required_scopes)
    if Authable.Utils.List.subset?(scopes, required_scopes) do
      {:ok, client}
    else
      GrantTypeError.invalid_scope(scopes)
    end
  end

  defp grant_type, do: "client_credentials"
end
