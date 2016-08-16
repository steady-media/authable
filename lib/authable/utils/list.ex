defmodule Authable.Utils.List do
  @moduledoc """
  List utilities
  """

  @doc """
  Check if a list superset of given list
  """
  def subset?(super_list, list) do
    Enum.find(list, fn(item) -> Enum.member?(super_list, item) == false end)
    |> is_nil
  end
end
