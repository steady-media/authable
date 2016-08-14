defmodule Authable.GrantType.Base do
  @moduledoc """
  Base module for OAuth2 grant types
  """

  @repo Application.get_env(:authable, :repo)
  @token_store Application.get_env(:authable, :token_store)
  @app Application.get_env(:authable, :app)
  @grant_types Application.get_env(:authable, :grant_types)

  @doc """
  A common function to generate oauth2 tokens (access_token and refresh_token)
  for all Authable.GrantType.

  To create oauth2 tokens, function requires valid 'resource owner model',
  'grant_type', 'client_id', 'scope' and as optional 'redirect_uri'.
  It automatically checks given scopes against configuration scopes and if any
  invalid scope occurs then it raises an exception with type of
  Authable.Error.SuspiciousActivity.
  It automatically checks the refresh_token strategy from configuration params
  and creates if enabled, otherwise it skips creation.

  ## Examples

      Authable.GrantType.Base.create_oauth2_tokens(user, "refresh_token",
        "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e", "read",
        "http://localhost:4000/oauth2/callbacks")
  """
  def create_oauth2_tokens(user_id, grant_type, client_id, scope, redirect_uri \\ nil) do
    scopes_check(scope)

    token_params = %{
      user_id: user_id,
      details: %{
        grant_type: grant_type,
        client_id: client_id,
        scope: scope,
        redirect_uri: redirect_uri
      }
    }

    token_params =
      if @grant_types[:refresh_token] do
        # create refresh_token
        refresh_token_changeset = @token_store.refresh_token_changeset(
          %@token_store{}, token_params
        )
        case @repo.insert(refresh_token_changeset) do
          {:ok, refresh_token} ->
            token_params |> Map.merge(%{details:
              Map.put(token_params[:details],
                :refresh_token, refresh_token.value)}
            )
          :error ->
            token_params
        end
      else
        token_params
      end

    access_token_changeset = @token_store.access_token_changeset(
      %@token_store{}, token_params
    )
    case @repo.insert(access_token_changeset) do
      {:ok, access_token} -> access_token
    end
  end

  @doc """
  A common function for all Authable.GrantType to check if the client
  authorized for the given resource owner. Returns either true or false,
  depending on status of authorization.

  ## Examples

      Authable.GrantType.Base.app_authorized?(
        "256a6d70-4a91-43fe-aacf-5588862ed8a2"
        "52024ca6-cf1d-4a9d-bfb6-9bc5023ad56e"
      )
  """
  def app_authorized?(user_id, client_id) do
    !is_nil(@repo.get_by(@app, user_id: user_id, client_id: client_id))
  end

  defp scopes_check(scopes) do
    valid_scopes = Application.get_env(:authable, :scopes)
    desired_scopes = Authable.Utils.String.comma_split(scopes)
    Enum.each(desired_scopes, fn(scope) -> scope_check(valid_scopes, scope) end)
  end

  defp scope_check(valid_scopes, scope) do
    unless Enum.member?(valid_scopes, scope) do
      raise Authable.Error.SuspiciousActivity,
        message: "Scope: #{scope} is not supported!"
    end
  end
end
