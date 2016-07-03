defmodule Authable.Renderer do
  @moduledoc """
  A behaviour for all renderer modules called by other authable modules.

  ## Creating a custom module

  If you are going to create a custom renderer module, then you need to
  implement following function:
    * `render`
  """

  @doc """
  Puts response body inside Plug.Conn and returns Plug.Conn
  """
  @callback render(Plug.Conn, Map) :: Plug.Conn
end
