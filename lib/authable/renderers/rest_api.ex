defmodule Authable.Rederer.RestApi do
  @moduledoc """
  An implementation for `Authable.Rederer` to render Authable errors in RestAPI
  format.
  """

  import Plug.Conn

  @behaviour Authable.Renderer

  def render(conn, status, map) do
    conn
    |> put_resp_content_type("application/json", "utf-8")
    |> resp(status, Poison.encode!(map))
  end
end