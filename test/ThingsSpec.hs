{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module ThingsSpec where

import Control.Monad (liftM)
import Control.Monad.Error.Class (MonadError, catchError, throwError)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (ExceptT, throwE)
import Crypto.Random.Types (MonadRandom, getRandomBytes)
import Data.Aeson
import Data.Proxy
import Data.String.Conversions (cs)
import Data.Text
import Network.Wai
import Servant.API
import Servant.OAuth.Grants (OAuthGrantOpaqueAssertion (..), OpaqueToken (..))
import Servant.OAuth.Grants.Facebook
import Servant.OAuth.JWT
import Servant.OAuth.TokenServer
import Servant.OAuth.TokenServer.Types
import Servant.Server
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher

------------------------------

type TokenServerAPI = "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] OAuthGrantFacebookAssertion

tokenServerApp :: IO Application
tokenServerApp = do
  signSettings <- mkTestJWTSignSettings
  pure $ serve (Proxy @TokenServerAPI) (runTokenServerM . tokenEndpointNoRefresh signSettings tokenHandler)

tokenHandler :: Monad m => OAuthGrantFacebookAssertion -> m (ClaimSub Text)
tokenHandler = pure . ClaimSub . cs . show

newtype TokenServerM a = TokenServerM {runTokenServerM :: Handler a}
  deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadRandom TokenServerM where
  getRandomBytes = undefined

instance MonadError ServerError TokenServerM where
  throwError = TokenServerM . Handler . throwE
  catchError = undefined

app :: IO Application
app = tokenServerApp

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
