module ThingsSpec where

import Data.Aeson
import Data.Proxy
import Data.Text
import Network.Wai
import Servant.API
import Servant.OAuth.Grants (OAuthGrantOpaqueAssertion (..), OpaqueToken (..))
import Servant.OAuth.Grants.Facebook
import Servant.OAuth.JWT (CompactJWT (..))
import Servant.OAuth.TokenServer
import Servant.OAuth.TokenServer.Types
import Servant.Server
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher

type API = "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] Text

app :: IO Application
app = do
  signSettings <- undefined
  pure $ serve (Proxy @API) $ tokenHandler signSettings

tokenHandler :: ToJWT Text => JWTSignSettings -> Either String Text -> Handler OAuthTokenSuccess
tokenHandler signSettings = tokenEndpointNoRefresh @Handler @Text @Text signSettings $ \_grant -> undefined

spec :: Spec
spec = with app $ do
  describe "facebook" $ do
    describe "fetch token" $ do
      it "success" $ do
        let reqbody :: OAuthGrantFacebookAssertion
            reqbody = OAuthGrantOpaqueAssertion (OpaqueToken "...")

            respbody :: OAuthTokenSuccess
            respbody = OAuthTokenSuccess (CompactJWT "jwt") 30 Nothing

        request "POST" "/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
          `shouldRespondWith` 200 {matchBody = bodyEquals $ encode respbody}

      it "failure" $ do
        pending

  describe "oidc" $ do
    pure () -- all of the above, again.
>>>>>>> 57826ac (Work on first test case.)
