defmodule Authable.GrantType.Password do
  @moduledoc """
  Password grant type for OAuth2 Authorization Server
  """

  import Authable.GrantType.Base
  alias Authable.Utils.Crypt, as: CryptUtil

  @behaviour Authable.GrantType
  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)
  @client Application.get_env(:authable, :client)
  @scopes Enum.join(Application.get_env(:authable, :scopes), ",")

  @doc """
  Authorize client for 'resouce owner' using resouce owner credentials and
  client identifier.

  For authorization, authorize function requires a map contains 'email' and
  'password', 'scope' and 'client_id'. With valid credentials;
  it automatically creates access_token and
  refresh_token(if enabled via config) then it returns
  access_token struct, otherwise {:error, Map, :http_status_code}.

  ## Examples

      Authable.GrantType.Password.authorize(%{
        "email" => "foo@example.com",
        "password" => "12345678",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e",
        "scope" => "read"
      %})

      Authable.GrantType.Password.authorize(%{
        "email" => "foo@example.com",
        "password" => "12345678",
        "client_id" => "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e"
      %})
  """
  def authorize(%{"email" => email, "password" => password, "client_id" => client_id, "scope" => scopes}) do
    client = @repo.get(@client, client_id)
    user = @repo.get_by(@resource_owner, email: email)
    create_tokens(client, user, password, scopes)
  end

  def authorize(%{"email" => email, "password" => password, "client_id" => client_id}) do
    client = @repo.get(@client, client_id)
    user = @repo.get_by(@resource_owner, email: email)
    create_tokens(client, user, password, @scopes)
  end

  def authorize(_), do: {:error,
    %{invalid_request: "Request must include at least email, password and client_id parameters."},
    :bad_request}

  defp create_tokens(nil, _, _, _), do: {:error,
    %{invalid_client: "Invalid client id."}, :unauthorized}
  defp create_tokens(client, nil, _, _), do: {:error,
    %{invalid_grant: "Identity not found."}, :bad_request}
  defp create_tokens(client, user, password, scopes) do
    {:ok, user}
    |> match_with_user_password(password)
    |> validate_token_scope(scopes)
    |> create_oauth2_tokens(client, scopes)
  end

  defp create_oauth2_tokens({:error, err, code}, _, _), do: {:error, err, code}
  defp create_oauth2_tokens({:ok, user}, client, scopes) do
    create_oauth2_tokens(
      user.id, grant_type, client.id, scopes, client.redirect_uri)
  end

  defp validate_token_scope({:error, err, code}, _), do: {:error, err, code}
  defp validate_token_scope({:ok, user}, ""), do: {:ok, user}
  defp validate_token_scope({:ok, user}, required_scopes) do
    scopes = @scopes |> String.split(",")
    required_scopes = required_scopes |> String.split(",")
    if Enum.find(required_scopes, fn(required_scope) ->
        Enum.member?(scopes, required_scope) == false end) do
      {:error, %{invalid_scope:
        "Allowed scopes for the token are #{Enum.join(scopes, ", ")}."},
        :bad_request}
    else
      {:ok, user}
    end
  end

  defp match_with_user_password({:error, err, code}, _), do: {:error, err, code}
  defp match_with_user_password({:ok, user}, password) do
    if CryptUtil.match_password(password, Map.get(user, :password, "")) do
      {:ok, user}
    else
      {:error,
        %{invalid_grant: "Identity, password combination is wrong."},
        :bad_request}
    end
  end

  defp grant_type, do: "password"
end
