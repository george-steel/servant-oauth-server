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

-- | generated with 'mkTestJWTSignSettings'
testJWTSignSettings :: JWTSignSettings
Just testJWTSignSettings =
  decode "{\"jwtDuration\":5,\"jwtInitialClaims\":{},\"jwtSignKey\":{\"crv\":\"Ed25519\",\"d\":\"ZfSXWx4QCq4mQW_lPOXGvcqfEy6757Q2s9gWK2YbV88\",\"key_ops\":[\"sign\",\"verify\"],\"kid\":\"RHKw2tjb43P5mMab0m_xpYbNpAaiXROLdaOR8so4joo\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"Rm-3PqAInCgSjdlqWJz1RKADlIajHLa5So-uY4R95EU\"}}"

------------------------------

type TokenServerAPI = "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] OAuthGrantFacebookAssertion

tokenServerApp :: IO Application
tokenServerApp = do
  pure $ serve (Proxy @TokenServerAPI) (runTokenServerM . tokenEndpointNoRefresh testJWTSignSettings tokenHandler)

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
  describe "fetch token" $ do
    it "success" $ do
      let reqbody :: OAuthGrantFacebookAssertion
          reqbody = OAuthGrantOpaqueAssertion (OpaqueToken "...")

          _respbody :: OAuthTokenSuccess
          _respbody = OAuthTokenSuccess (CompactJWT "...") 5 Nothing

      -- TODO: `200 {matchBody = bodyEquals $ encode respbody}` (but that requires reproducible randomness in the token server.)
      request "POST" "/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
        `shouldRespondWith` 200

    it "failure" $ do
      pending
