{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, OverloadedStrings,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators #-}
module Servant.OAuth.Server where

import Crypto.JWT
import Servant.API
import Servant.Server
import Servant.Server.Internal.RoutingApplication
import Network.Wai (Request, requestHeaders)

import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Arrow
import Control.Lens
import Data.Proxy
import Data.Aeson
import Data.Maybe

import Servant.OAuth.Grants



data SomeJWKResolver where
    SomeJWKResolver :: (VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) ClaimsSet k) => k -> SomeJWKResolver

data JWTSettings = JWTSettings SomeJWKResolver JWTValidationSettings


data AuthError =
    AuthRequired Text
    | InvalidAuthRequest Text
    | InvalidToken Text
    | InsufficientScope Text
    deriving (Eq, Read, Show)

authErrorServant :: AuthError -> ServantErr
authErrorServant (AuthRequired msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidAuthRequest msg) = err400 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_request\"")], errBody = "Malformed authorization header: " <> BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidToken msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_token\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InsufficientScope msg) = err403 {errHeaders = [("WWW-Authenticate", "Bearer error=\"insufficient_scope\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}

throwForbidden :: (MonadError ServantErr m) => Text -> m a
throwForbidden = throwError . authErrorServant . InsufficientScope

throwForbiddenOrLogin :: (FromJWT auth, MonadError ServantErr m) => Maybe auth -> Text -> m a
throwForbiddenOrLogin (Just _) = throwForbidden
throwForbiddenOrLogin Nothing = throwError . authErrorServant . AuthRequired


class FromJWT a where
    fromJWT :: ClaimsSet -> Either Text a
    default fromJWT :: (FromHttpApiData a) => ClaimsSet -> Either Text a
    fromJWT claims = parseQueryParam =<< maybe (Left "sub claim not found") Right (claims ^? claimSub . _Just . string)

instance (FromJWT a, FromJWT b) => FromJWT (a,b) where
    fromJWT claims = (,) <$> fromJWT claims <*> fromJWT claims

instance (FromJWT a) => FromJWT (Maybe a) where
    fromJWT claims = either (const (Right Nothing)) (Right . Just) (fromJWT claims)



checkAuthToken :: (FromJWT a) => JWTSettings -> CompactJWT -> IO (Either JWTError a)
checkAuthToken (JWTSettings (SomeJWKResolver keys) valsettings) (CompactJWT ctok) = runExceptT $ do
    tok <- decodeCompact . BL.fromStrict . T.encodeUtf8 $ ctok
    claims <- verifyClaims valsettings keys tok
    let mx = fromJWT claims
    either (throwError . JWTClaimsSetDecodeError . unpack) return mx


data AuthRequired a
data AuthOptional a

checkJwtLogin :: (FromJWT a) => JWTSettings -> Request -> DelayedIO (Maybe a)
checkJwtLogin settings req = case lookup "Authorization" (requestHeaders req) of
    Nothing -> return Nothing
    Just hdr -> do
        tok <- case parseHeader hdr of
            Left msg -> delayedFailFatal . authErrorServant $ InvalidAuthRequest msg
            Right t -> return t
        mauth <- liftIO $ checkAuthToken settings tok
        case mauth of
            Left err -> delayedFailFatal . authErrorServant . InvalidToken . pack . show $ err
            Right auth -> return (Just auth)

instance (HasServer api context, HasContextEntry context JWTSettings, FromJWT a) => HasServer (AuthRequired a :> api) context where
    type ServerT (AuthRequired a :> api) m = a -> ServerT api m

    route Proxy context subserver = route (Proxy :: Proxy api) context (addAuthCheck subserver authCheck) where
        authCheck = withRequest $ requireLogin <=< checkJwtLogin (getContextEntry context)
        requireLogin = maybe (delayedFailFatal . authErrorServant $ AuthRequired "Login Required") return

    hoistServerWithContext _ pc f s = hoistServerWithContext (Proxy :: Proxy api) pc f . s

instance (HasServer api context, HasContextEntry context JWTSettings, FromJWT a) => HasServer (AuthOptional a :> api) context where
    type ServerT (AuthOptional a :> api) m = Maybe a -> ServerT api m

    route Proxy context subserver = route (Proxy :: Proxy api) context (addAuthCheck subserver authCheck) where
        authCheck = withRequest $ checkJwtLogin (getContextEntry context)

    hoistServerWithContext _ pc f s = hoistServerWithContext (Proxy :: Proxy api) pc f . s
