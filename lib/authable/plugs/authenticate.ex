defmodule Authable.Plug.Authenticate do
  @moduledoc """
  Authable plug implementation to check authentications and
  to set resouce owner.
  """

  import Plug.Conn

  @behaviour Plug
  @renderer Application.get_env(:authable, :renderer)

  def init(opts) do
    [
      scopes: Keyword.get(opts, :scopes, ""),
      halt: Keyword.get(opts, :halt, true)
    ]
  end

  @doc """
  Plug function to authenticate client for resouce owner and assigns resource
  owner into conn.assigns[:current_user] key.
  If it fails, then it halts connection and returns :bad_request, :unauthorized
  or :forbidden status codes with error json.

  However, if it fails, but the option `:halt` is set to false, it does nothing.

  There are two options:

    * scopes - the function used to authorize the resource access (default: "")
    * halt - whether to halt the connection in case of authorization failure (default: true)

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
  def call(conn, [scopes: scopes, halt: halt]) do
    response_conn_with(conn, Authable.Helper.authorize_for_resource(conn,
      scopes), halt)
  end

  defp response_conn_with(conn, nil, true) do
    conn
    |> put_resp_header("www-authenticate", "Bearer realm=\"authable\"")
    |> @renderer.render(:forbidden, %{errors: %{details: "Resource access requires authentication!"}})
    |> halt
  end
  defp response_conn_with(conn, {:error, errors, http_status_code}, true) do
    [%{"www-authenticate" => header_val}] = errors[:headers]
    errors = %{errors: Map.delete(errors, :headers)}
    conn
    |> put_resp_header("www-authenticate", header_val)
    |> @renderer.render(http_status_code, %{errors: errors})
    |> halt
  end
  defp response_conn_with(conn, {:ok, current_user, current_token}, _) do
    conn
    |> assign(:current_user, current_user)
    |> assign(:current_token, current_token)
  end
  defp response_conn_with(conn, _, false) do
    conn
  end
end
