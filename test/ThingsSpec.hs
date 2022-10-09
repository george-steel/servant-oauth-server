{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module ThingsSpec where

import Control.Lens
import Control.Monad (liftM)
import Control.Monad.Error.Class (MonadError, catchError, throwError)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (ExceptT, throwE)
import Crypto.JWT (StringOrURI, defaultJWTValidationSettings)
import Crypto.Random.Types (MonadRandom, getRandomBytes)
import Data.Aeson
import qualified Data.Aeson.Lens as A
import Data.Maybe (fromJust)
import Data.Proxy
import Data.String
import Data.String.Conversions (cs)
import Data.Text
import Network.Wai
import Network.Wai.Test (SRequest (..), simpleBody)
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

testJWTSettings :: JWTSettings
testJWTSettings =
  JWTSettings
    (SomeJWKResolver (jwtSignKey testJWTSignSettings))
    (defaultJWTValidationSettings (== tokenPayload))

tokenPayload :: IsString s => s
tokenPayload = "..."

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

type API =
  "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] OAuthGrantFacebookAssertion
    :<|> "login" :> AuthRequired (ClaimSub Text) :> Get '[JSON] Text
    :<|> "login-optional" :> AuthOptional (ClaimSub Text) :> Get '[JSON] Text

app :: IO Application
app =
  pure . serveWithContext (Proxy @API) (testJWTSettings :. EmptyContext) $
    ( runAppM . tokenEndpointNoRefresh testJWTSignSettings tokenHandler
        :<|> runAppM . resourceHandler . Just
        :<|> runAppM . resourceHandler
    )

tokenHandler :: Monad m => OAuthGrantFacebookAssertion -> m (ClaimSub Text)
tokenHandler = pure . ClaimSub . cs . show

resourceHandler :: Maybe (ClaimSub Text) -> AppM Text
resourceHandler = pure . cs . encode

------------------------------

spec :: Spec
spec = with app $ do
  describe "fetch token" $ do
    it "success case" $ do
      let reqbody :: OAuthGrantFacebookAssertion
          reqbody = OAuthGrantOpaqueAssertion (OpaqueToken tokenPayload)

      -- TODO: `200 {matchBody = bodyEquals $ encode (OAuthTokenSuccess (CompactJWT tokenPayload) 5 Nothing)}`
      -- (but that requires reproducible randomness in the token server.)
      request "POST" "/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
        `shouldRespondWith` 200

    it "failure case" $ do
      pending

  describe "present token to resource server" $ do
    it "success case" $ do
      resp <- do
        let reqbody = OAuthGrantOpaqueAssertion (OpaqueToken tokenPayload) :: OAuthGrantFacebookAssertion
        request "POST" "/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
      let Just token = decode @Value (simpleBody resp) >>= (^? A.key ("access_token" :: Key) . A._String)
      request "GET" "/login" [("Content-type", "application/json"), ("Authorization", "Bearer " <> cs token)] mempty
        `shouldRespondWith` 200 {matchBody = bodyEquals . cs . show $ "\"OAuthGrantOpaqueAssertion (OpaqueToken \\\"...\\\")\""}

    it "failure case" $ do
      pending
