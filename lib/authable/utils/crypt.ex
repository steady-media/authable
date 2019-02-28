defmodule Authable.Utils.Crypt do
  @moduledoc """
  Crypt utilities
  """

  @doc """
  Compares string with Bcrypted version of the string.

  Returns true if mathes, otherwise false

  ## Examples

      Authable.Utils.Crypt.match_password("12345678",
        "$2b$12$wHkoEnYQ03mWH1CsByPB4ek4xu7QXIFYl5gAC6b8zYs3aj/9DNv3u"
      )
  """
  def match_password(password, crypted_password) do
    Bcrypt.verify_pass(password, crypted_password)
  end

  @doc """
  Generate a salt from given string.

  Returns crypted string

  ## Examples

      Authable.Utils.Crypt.salt_password("12345678")
      # "$2b$12$wHkoEnYQ03mWH1CsByPB4ek4xu7QXIFYl5gAC6b8zYs3aj/9DNv3u"
  """
  def salt_password(password) do
    Bcrypt.hash_pwd_salt(password)
  end

  @doc """
  Generates a random string

  ## Examples

      Authable.Utils.Crypt.generate_token
      # "ve7LXBsGqsvsXXjiFS1PVQ"
  """
  def generate_token do
    SecureRandom.urlsafe_base64
  end
end
