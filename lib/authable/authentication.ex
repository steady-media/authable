defmodule Authable.Authentication do
  @moduledoc """
  A behaviour for all authentications modules called by other authable modules.

  ## Creating a custom module

  If you are going to create a custom authentication module, then you need to
  implement following function:
    * `authenticate`
  """

  @doc """
  Finds and returns Resource Owner(User) struct using a param(param can be any
  type).

  This function returns a `{:ok, Authable.Model.User struct}` or
  `{:error, Map, :http_status_code}`.
  """
  @callback authenticate(any, List) :: {:ok, Application.get_env(:authable,
    :resource_owner)} | {:error, Map, Atom}
end
