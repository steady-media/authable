defmodule Authable.AuthStrategy.Session do
  @moduledoc """
  Authable Strategy implements behaviour Authable.Strategy to check 'session'
  based authencations to find resource owner.
  """

  import Plug.Conn, only: [fetch_session: 1, get_session: 2]

  @behaviour Authable.AuthStrategy
  @auth_strategies Application.get_env(:authable, :auth_strategies)
  @session_auth Map.get(@auth_strategies, :sessions)

  @doc """
  Finds resource owner using configured 'session' keys. Returns nil if
  either no keys are configured or key value not found in the session.
  And, it returns resource_owner on sucess,
  {:error, Map, :http_status_code} on fails.
  """
  def authenticate(conn, _) do
    if @session_auth, do: authenticate_via_session(conn, @session_auth)
  end

  defp authenticate_via_session(conn, session_auth) do
    Enum.find_value(session_auth, fn {key, module} ->
      session_value = conn |> fetch_session |> get_session(key)
      if !is_nil(session_value) do
        module.authenticate(session_value, [])
      end
    end)
  end
end
