module ThingsSpec where

import Data.Aeson
import Data.Proxy
import Data.Text
import Network.Wai
import Servant.API
import Servant.OAuth.Grants (OAuthGrantOpaqueAssertion (..), OpaqueToken (..))
import Servant.OAuth.Grants.Facebook
import Servant.OAuth.JWT
import Servant.OAuth.JWT (CompactJWT (..))
import Servant.OAuth.TokenServer
import Servant.OAuth.TokenServer.Types
import Servant.Server
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher

------------------------------

type API = "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] Text

app :: IO Application
app = do
  signSettings <- mkTestJWTSignSettings
  pure $ serve (Proxy @API) $ tokenEndpointNoRefresh signSettings tokenHandler

tokenHandler :: forall grant claims. Text -> Handler (ClaimSub Text)
tokenHandler = pure . ClaimSub

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
