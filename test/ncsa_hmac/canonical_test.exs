defmodule NcsaHmac.CanonicalTest do
  use ExUnit.Case

  test "it creates the string as expected" do
    output = NcsaHmac.Canonical.string("POST", "/some/api/path", "2017-07-11T12:12:12Z", "123edr456tfg", "application/json")
    expected = "POST\napplication/json\n123edr456tfg\n2017-07-11T12:12:12Z\n/some/api/path"
    assert output == expected
  end

  test "it downcases the path" do
    output = NcsaHmac.Canonical.string("PUT", "/sOMe/API/pAtH", "2017-07-11T12:12:12Z", "123edr456tfg", "application/json")
    expected = "PUT\napplication/json\n123edr456tfg\n2017-07-11T12:12:12Z\n/some/api/path"
    assert output == expected
  end

  test "it sets default values for content_digest and content_type" do
    output = NcsaHmac.Canonical.string("GET", "/some/api/path", "2017-07-11T12:12:12Z")
    expected = "GET\napplication/json\n\n2017-07-11T12:12:12Z\n/some/api/path"
    assert output == expected
  end

  test "it ignores the content_digest for GET requests" do
    output = NcsaHmac.Canonical.string("GET", "/some/api/path", "2017-07-11T12:12:12Z", "123edr456tfg", "application/json")
    expected = "GET\napplication/json\n\n2017-07-11T12:12:12Z\n/some/api/path"
    assert output == expected
  end
end
