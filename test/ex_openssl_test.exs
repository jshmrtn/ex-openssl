defmodule ExOpensslTest do
  use ExUnit.Case
  doctest ExOpenssl

  test "greets the world" do
    assert ExOpenssl.hello() == :world
  end
end
