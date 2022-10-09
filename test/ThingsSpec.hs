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
import Servant.OAuth.ResourceServer
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

newtype AppM a = AppM {runAppM :: Handler a}
  deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadRandom AppM where
  getRandomBytes =
    -- TODO: why isn't this catching?  are we just adding a determinstic digest instead of the ec25519 signature?
    undefined

instance MonadError ServerError AppM where
  throwError = AppM . Handler . throwE
  catchError (AppM action) handler = AppM (action `catchError` (runAppM . handler))

------------------------------

type TokenAPI = "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] OAuthGrantFacebookAssertion

tokenApp :: IO Application
tokenApp = do
  pure $ serve (Proxy @TokenAPI) (runAppM . tokenEndpointNoRefresh testJWTSignSettings tokenHandler)

tokenHandler :: Monad m => OAuthGrantFacebookAssertion -> m (ClaimSub Text)
tokenHandler = pure . ClaimSub . cs . show

------------------------------

type ResourceAPI = "login" :> AuthRequired CompactJWT :> Get '[JSON] Bool

resourceApp :: IO Application
resourceApp = do
  undefined -- pure $ serve (Proxy @ResourceAPI) (runAppM . undefined)

------------------------------

spec :: Spec
spec = do
  describe "fetch token" . with tokenApp $ do
    it "success case" $ do
      let reqbody :: OAuthGrantFacebookAssertion
          reqbody = OAuthGrantOpaqueAssertion (OpaqueToken "...")

          _respbody :: OAuthTokenSuccess
          _respbody = OAuthTokenSuccess (CompactJWT "...") 5 Nothing

      -- TODO: `200 {matchBody = bodyEquals $ encode respbody}` (but that requires reproducible randomness in the token server.)
      request "POST" "/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
        `shouldRespondWith` 200

    it "failure case" $ do
      pending

  describe "present token to resource server" . with resourceApp $ do
    it "success case" $ do
      pending

    it "failure case" $ do
      pending
