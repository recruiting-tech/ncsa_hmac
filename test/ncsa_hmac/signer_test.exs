defmodule NcsaHmac.SignerTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias NcsaHmac.Signer
  # doctest NcsaHmac

  @key_id "SECRET_KEY_ID"
  @signing_key "abcdefghijkl"
  @target_md5_hash "ecadfcaf838cc3166d637a196530bd90"
  @target_body %{"abc" => "def"}
  @expected_sha512_signature "svO1jOUW+3wSVc/rzs4WQSOsWtABji6ppN0AkS++2SNvt6fPPvxonLV5WRgFaqnVc63RNmAndel8e/hxoNB4Pg=="
  @request_details %{
    "path" => "/api/auth",
    "method" => "POST",
    "params" => @target_body,
    "date" => "Fri, 22 Jul 2016",
    "content-type" => "application/json",
    "content-digest" => @target_md5_hash
  }

  test "do not set content-digest if the body is empty" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> @expected_sha512_signature

    signature =  Signer.sign(@request_details, @key_id, @signing_key)
    assert signature == auth_string
  end

  test "handle urls params as a string" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> "obUmKdcBReDl2ovTb0wKQHB1kPBU2ksKEqKC9fQ9OKF/9p8c9HLjdKnXpw+TqeiGOtKGZPPq/C8isWVVqEdAmw=="
    request_details = Map.update!(@request_details, "params", fn(_) -> "abc=def" end )
    signature =  Signer.sign(request_details, @key_id, @signing_key)

    assert signature == auth_string
  end

  test "handle mutiple urls params as a string" do
    auth_string = "NCSA.HMAC " <> @key_id <> ":" <> "nTFG2IxI5REJpfFgSkk0NmhnovaprbmLbUUlr+pVPVRs95NF0aaF1Q3prZSA+DVLVDLLkvSfG5bPsZALD6cXBw=="
    request_details = Map.update!(@request_details, "params", fn(_) -> "abc=def&def=ghi" end )
    signature =  Signer.sign(request_details, @key_id, @signing_key)

    assert signature == auth_string
  end

  test "set the date when none is passed in the request" do
    request_details = Map.delete(@request_details, "date")
    canonical = Signer.canonicalize_request(request_details)
    {:ok, strftime} = Timex.Format.DateTime.Formatter.format(Timex.now, "%FT%R", :strftime)

    assert String.contains?(canonical, strftime)
  end

  test "canonical message content" do
    date = "1234"
    request_details = Map.update!(@request_details, "date", fn(_) -> date end)
    canonical = Signer.canonicalize_request(request_details)

    assert canonical == "POST" <> "\n"
      <> "application/json" <> "\n"
      <> @target_md5_hash <> "\n"
      <> date <> "\n"
      <> "/api/auth"
  end

  test "canonical message content UPCASE method and downcase path" do
    date = "1234"
    request_details = Map.update!(@request_details, "method", fn(_) -> "post" end)
      |> Map.update!("date", fn(_) -> date end)
      |> Map.update!("path", fn(_) -> "/aPi/AUth" end)
    canonical = Signer.canonicalize_request(request_details)

    assert canonical == "POST" <> "\n"
      <> "application/json" <> "\n"
      <> @target_md5_hash <> "\n"
      <> date <> "\n"
      <> "/api/auth"
  end


  test "computed signature matches a known SHA512 signature" do
    signature = Signer.signature(@request_details, @signing_key)
    assert signature == @expected_sha512_signature
  end

  test "computed signature matches a known SHA384 signature" do
    expected_sha384_signature = "LkXSygPRNKTuqHxUEzM6iUxLnTW4I4D+G7JxVDHKj1l/7qeb/i9rp8aX+b7eW0YN"
    signature = Signer.signature(@request_details, @signing_key, :sha384)
    assert signature == expected_sha384_signature
  end

  test "computed signature matches a known SHA256 signature" do
    expected_sha256_signature = "FzfelqPkbfyA2WK/ANhBB4vlqdXQ5m1h53fELgN5QB4="
    signature = Signer.signature(@request_details, @signing_key, :sha256)
    assert signature == expected_sha256_signature
  end

  test "computed signature matches when content_type == '' " do
    expected_signature = "u8+hRiEYpt+cDoOdx0Lt6Ymmw2bc3iA02l3rVEg9en3WPWEAS1yG9It94ds3/bkQmexnS+dNsQ3km8Ewc5Jj7w=="
    request_details = Map.update!(@request_details, "content-type", fn(_) -> "" end)
    signature = Signer.signature(request_details, @signing_key)
    assert signature == expected_signature
  end

  test "Missing key_id throws an exception" do
    assert_raise(NcsaHmac.SigningError, fn ->
        Signer.sign(@request_details, nil, @signing_key)
      end
    )
    assert_raise(NcsaHmac.SigningError, fn ->
        Signer.sign(@request_details, "", @signing_key)
      end
    )
  end

  test "Missing key_secret throws an exception" do
    assert_raise(NcsaHmac.SigningError, fn ->
        Signer.sign(@request_details, @key_id, nil)
      end
    )
    assert_raise(NcsaHmac.SigningError, fn ->
        Signer.sign(@request_details, @key_id, "")
      end
    )
  end
end
