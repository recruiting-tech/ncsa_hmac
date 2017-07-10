Code.load_file("test/support/repo_setup.ex")
Application.put_env :ncsa_hmac, :repo, Repo

ExUnit.start()
