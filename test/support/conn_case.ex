defmodule Authable.ConnCase do
  @moduledoc """
  Conveniences for testing Plug endpoints
  """

  @doc false
  defmacro __using__(_) do
    quote do
      use Authable.ConnTest
    end
  end
end
