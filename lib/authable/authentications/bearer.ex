defmodule Authable.Authentication.Bearer do
  @moduledoc """
  Bearer authencation helper module
  """

  alias Authable.Authentication.Token, as: TokenAuthentication

  @behaviour Authable.Authentication

  @doc """
  Authenticates resource-owner using access_token map.

  It reads access_token value from given input and delegates value to
  Authable.Authentication.Bearer.authenticate/1 function.

  ## Examples

      # Suppose we have a access_token at 'token store(Authable.Token)'
      # with token value "at123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentication.Bearer.authenticate(
       %{"access_token" => "at123456789"}, ["read"])
  """
  def authenticate(%{"access_token" => access_token}, required_scopes) do
    authenticate(access_token, required_scopes)
  end

  @doc """
  Authenticates resource-owner using access_token token value.

  It matches resource owner with given access_token. If any resource owner
  matched given credentials, it returns {:ok, resource owner struct}, otherwise
  {:error, Map, :http_status_code}

  ## Examples

      # Suppose we have a access_token at 'token store(Authable.Token)'
      # with token value "at123456789"
      # If we pass the token value to the function,
      # it will return resource-owner.
      Authable.Authentication.Bearer.authenticate("at123456789")
  """
  def authenticate(access_token, required_scopes) do
    case TokenAuthentication.authenticate(
      {"access_token", access_token}, required_scopes) do
        {:ok, user} -> {:ok, user}
        {:error, errors, status} -> {:error,
          Map.put(errors, :headers, bearer_error_header(errors)), status}
    end
  end

  defp bearer_error_header(errors) do
    error_message = generate_error_message(errors)
    [%{"www-authenticate" => "Bearer realm=\"authable\", ${error_message}"}]
  end

  defp generate_error_message(errors) do
    "error=\"${Map.keys(errors)}\",
      error_description=\"${Map.values(errors)}\""
  end
end
