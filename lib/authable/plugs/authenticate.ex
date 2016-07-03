defmodule Authable.Plug.Authenticate do
  @moduledoc """
  Authable plug implementation to check authentications and
  to set resouce owner.
  """

  import Plug.Conn

  @behaviour Plug
  @rederer Application.get_env(:authable, :renderer)

  def init(opts) do
    Keyword.get opts, :scopes, ""
  end

  @doc """
  Plug function to authenticate client for resouce owner and assigns resource
  owner into conn.assigns[:current_user] key.
  If it fails, then it halts connection and returns :bad_request, :unauthorized
  or :forbidden status codes with error json.

  There is one option:

    * scopes - the function used to authorize the resource access
    * the default is ""

  ## Examples

      defmodule SomeModule.AppController do
        use SomeModule.Web, :controller
        plug Authable.Plug.Authenticate, [scopes: ~w(read write)]

        def index(conn, _params) do
          # access to current user on successful authentication
          current_user = conn.assigns[:current_user]
          ...
        end
      end

      defmodule SomeModule.AppController do
        use SomeModule.Web, :controller

        plug Authable.Plug.Authenticate [scopes: ~w(read write)] when action in [:create]

        def index(conn, _params) do
          # anybody can call this action
          ...
        end

        def create(conn, _params) do
          # only logged in users can access this action
          current_user = conn.assigns[:current_user]
          ...
        end
      end
  """
  def call(conn, scopes) do
    response_conn_with(conn, Authable.Helper.authorize_for_resource(conn,
      scopes))
  end

  defp response_conn_with(conn, nil) do
    conn
    |> put_status(:forbidden)
    |> put_resp_header("www-authenticate", "Bearer realm=\"authable\"")
    |> @rederer.render(%{errors: %{detail: "Resource access requires authentication!"}})
    |> halt
  end
  defp response_conn_with(conn, {:error, errors, http_status_code}) do
    [%{"www-authenticate" => header_val}] = errors[:headers]
    errors = %{errors: Map.delete(errors, :headers)}
    conn
    |> put_status(http_status_code)
    |> put_resp_header("www-authenticate", header_val)
    |> @rederer.render(errors)
    |> halt
  end
  defp response_conn_with(conn, {:ok, current_user}), do: assign(conn,
    :current_user, current_user)
end
