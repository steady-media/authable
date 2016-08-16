defmodule Authable.Utils.ListTest do
  use ExUnit.Case
  import Authable.Utils.List

  test "subset?#true" do
    super_list = [1, 2, 3, 4, 5]
    assert subset?(super_list, [3, 5])
    assert subset?(super_list, [1])
    assert subset?(super_list, [])
  end

  test "subset?#false" do
    super_list = [1, 2, 3, 4, 5]
    refute subset?(super_list, [3, 5, 6])
    refute subset?(super_list, [1, 2, 3, 4, 5, 6])
  end
end
