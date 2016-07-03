defmodule Authable.Rederer.RestApi do
  @moduledoc """
  An implementation for `Authable.Rederer` to render Authable errors in RestAPI
  format.
  """

  import Plug.Conn

  def render(conn, map) do
    conn
    |> put_resp_content_type("application/json", "utf-8")
    |> Map.put(:resp_body, Poison.encode!(map))
    |> Map.put(:state, :sent)
  end
end