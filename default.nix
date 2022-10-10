{ mkDerivation, aeson, base, bytestring, cryptonite, hspec
, hspec-discover, hspec-wai, http-api-data, http-client, http-types
, jose, lens, lens-aeson, lib, mtl, servant, servant-server
, string-conversions, text, time, transformers
, unordered-containers, wai, wai-extra
}:
mkDerivation {
  pname = "servant-oauth-server";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring cryptonite http-api-data http-client
    http-types jose lens mtl servant servant-server string-conversions
    text time unordered-containers wai
  ];
  testHaskellDepends = [
    aeson base bytestring cryptonite hspec hspec-wai http-api-data
    http-client http-types jose lens lens-aeson mtl servant
    servant-server string-conversions text time transformers
    unordered-containers wai wai-extra
  ];
  testToolDepends = [ hspec-discover ];
  homepage = "https://github.com/george-steel/servant-oauth-server#readme";
  description = "OAuth2 bearer token auth and token endpoint for Servant";
  license = lib.licenses.bsd3;
}
