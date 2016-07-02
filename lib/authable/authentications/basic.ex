defmodule Authable.Authentication.Basic do
  @moduledoc """
  Basic authentication helper module
  """

  alias Authable.Utils.Crypt, as: CryptUtil

  @behaviour Authable.Authentication
  @repo Application.get_env(:authable, :repo)
  @resource_owner Application.get_env(:authable, :resource_owner)

  @doc """
  Authenticates resource-owner using Basic Authentication header value.

  It handles the decoding the 'Authorization: Basic {auth_credentials}'
  and matches resource owner with given email and password. Since Basic auth
  requires identity and password, it does not require any scope check for
  authorization.
  If any resource owner matched given credentials,
  it returns {:ok, resource owner struct}, otherwise
  {:error, Map, :http_status_code}

  ## Examples

      # Suppose we have a resource owner with
      # email: foo@example.com and password: 12345678.
      # Base 64 encoding of email:password combination will be
      # 'Zm9vQGV4YW1wbGUuY29tOjEyMzQ1Njc4'. If we pass the encoded value
      # to the function, it will return resource-owner
      Authable.Authentication.Basic.authenticate(
        "Zm9vQGV4YW1wbGUuY29tOjEyMzQ1Njc4", [])

      Authable.Authentication.Basic.authenticate(
        "Basic Zm9vQGV4YW1wbGUuY29tOjEyMzQ1Njc4", [])
  """
  def authenticate(auth_credentials, _required_scopes) do
    authenticate_with_credentials(auth_credentials)
  end

  defp authenticate_with_credentials(auth_credentials) do
    auth_credentials = auth_credentials
                       |> String.split(" ", trim: true)
                       |> List.last
    case Base.decode64(auth_credentials) do
      {:ok, credentials} ->
        [email, password] = String.split(credentials, ":")
        authenticate_with_credentials(email, password)
      :error -> {:error, %{invalid_hash: "Invalid credentials encoding."},
        :unauthorized}
    end
  end

  defp authenticate_with_credentials(email, password) do
    case @repo.get_by(@resource_owner, email: email) do
      user ->
        case match_with_user_password(password, user) do
          true -> {:ok, user}
          false -> {:error, %{wrong_password:
            "Identity, password combination is wrong."}, :unauthorized}
        end
      nil ->
        {:error, %{identity_not_found: "Identity not found."}, :unauthorized}
    end
  end

  defp match_with_user_password(password, user) do
    CryptUtil.match_password(password, Map.get(user, :password, ""))
  end
end
