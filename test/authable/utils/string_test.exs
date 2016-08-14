defmodule Authable.Utils.StringTest do
  use ExUnit.Case
  import Authable.Utils.String

  test "split a string with comma" do
    str = "a, b, c   , d"
    assert comma_split(str) == ["a", "b", "c", "d"]
  end
end
