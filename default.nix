{ mkDerivation, aeson, base, bytestring, http-api-data, http-client
, http-types, jose, lens, lib, mtl, servant, servant-server, text
, time, unordered-containers, wai
}:
mkDerivation {
  pname = "servant-oauth-server";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring http-api-data http-client http-types jose
    lens mtl servant servant-server text time unordered-containers wai
  ];
  homepage = "https://github.com/george-steel/servant-oauth-server#readme";
  description = "OAuth2 bearer token auth and token endpoint for Servant";
  license = lib.licenses.bsd3;
}
