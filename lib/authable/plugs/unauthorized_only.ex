defmodule Authable.Plug.UnauthorizedOnly do
  @moduledoc """
  Authable plug implementation to refute authencated users to access resources.
  """

  import Plug.Conn
  alias Authable.AuthStrategy.Session, as: SessionAuthStrategy
  alias Authable.AuthStrategy.QueryParam, as: QueryParamAuthStrategy
  alias Authable.AuthStrategy.Header, as: HeaderAuthStrategy

  @behaviour Plug
  @rederer Application.get_env(:authable, :renderer)

  def init([]), do: false

  @doc """
  Plug function to refute authencated users to access resources.

  ## Examples

      defmodule SomeModule.AppController do
        use SomeModule.Web, :controller
        plug Authable.Plug.UnauthorizedOnly when action in [:register]

        def register(conn, _params) do
          # only not logged in user can access this action
        end
      end
  """
  def call(conn, _opts) do
    response_conn_with(conn, Authable.Helper.authorize_for_resource(conn, ""))
  end

  defp response_conn_with(conn, nil), do: conn
  defp response_conn_with(conn, {:error, errors, http_status_code}), do: conn
  defp response_conn_with(conn, user) do
    conn
    |> put_status(:bad_request)
    |> @rederer.render(%{errors: %{detail: "Only unauhorized access allowed!"}})
    |> halt
  end
end
