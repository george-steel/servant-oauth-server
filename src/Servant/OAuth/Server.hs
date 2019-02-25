{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, OverloadedStrings,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators #-}

{-|
Module: Servant.OAuth.Server
Description: JWT beraer token API combinators
Copyright: © 2018-2019 Satsuma labs, 2019 George Steel

This module defines Servant API compnators which check or require OAuth2 bearer token authorization for use in resource servers.
Access tokens are assumed to be self-enoded using JWT, with no particular structure assumed about identity/authorization claims.
Claim types should implement the 'FromJWT' typeclass.

-}

module Servant.OAuth.Server where

import Crypto.JWT
import Servant.API
import Servant.Server
import Servant.Server.Internal.RoutingApplication
import Network.Wai (Request, requestHeaders)

import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Lens
import Data.Proxy

import Servant.OAuth.Grants


-- | Extential type for a source of token verification keys.
-- Usually this will just wrap a 'JWKSet' but other types are possible (such as an action to ketch the public keys from an authorization server).
data SomeJWKResolver where
    SomeJWKResolver :: (VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) ClaimsSet k) => k -> SomeJWKResolver

-- | JWT verification settings to put into the servant context.
-- the validation settings must include a check of the @aud@ claim and should include a check of the @iss@ claim.
data JWTSettings = JWTSettings SomeJWKResolver JWTValidationSettings

-- | Class for data which reperesents a JWT claim. Default instance parses the @sub@ claim.
class FromJWT a where
    fromJWT :: ClaimsSet -> Either Text a
    default fromJWT :: (FromHttpApiData a) => ClaimsSet -> Either Text a
    fromJWT claims = parseQueryParam =<< maybe (Left "sub claim not found") Right (claims ^? claimSub . _Just . string)

-- | Parses both claims in the pair.
instance (FromJWT a, FromJWT b) => FromJWT (a,b) where
    fromJWT claims = (,) <$> fromJWT claims <*> fromJWT claims

-- | Makes a claim optional. Parsing always succeeds: errors in the wrapped claim result in a 'Nothing' value.
instance (FromJWT a) => FromJWT (Maybe a) where
    fromJWT claims = either (const (Right Nothing)) (Right . Just) (fromJWT claims)


-- * API combinators

-- | API combinator to require bearer token authorization, capturing the claims.
data AuthRequired a

-- | API combinator which captures token claims but does not require a token.
-- The captured claims are wrapped in 'Maybe' to handle the anonypus case.
-- Use this for an endpoint with mixed public and private content (possibly depending on a paramater).
data AuthOptional a

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

-- | Checks a JWT for valifity and returns the required claims.
checkAuthToken :: (FromJWT a) => JWTSettings -> CompactJWT -> IO (Either JWTError a)
checkAuthToken (JWTSettings (SomeJWKResolver keys) valsettings) (CompactJWT ctok) = runExceptT $ do
    tok <- decodeCompact . BL.fromStrict . T.encodeUtf8 $ ctok
    claims <- verifyClaims valsettings keys tok
    let mx = fromJWT claims
    either (throwError . JWTClaimsSetDecodeError . unpack) return mx

-- | Authorization check returning the correct error messages.
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

-- * Errors

-- | OAuth2 auhorization error for resource servers.
data AuthError =
    AuthRequired Text
    | InvalidAuthRequest Text
    | InvalidToken Text
    | InsufficientScope Text
    deriving (Eq, Read, Show)

-- | Convert an authorization error into a 'ServantErr' with correct response code and body
authErrorServant :: AuthError -> ServantErr
authErrorServant (AuthRequired msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidAuthRequest msg) = err400 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_request\"")], errBody = "Malformed authorization header: " <> BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidToken msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_token\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InsufficientScope msg) = err403 {errHeaders = [("WWW-Authenticate", "Bearer error=\"insufficient_scope\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}

-- | Throw an insufficient scope (403) error with a given message.
throwForbidden :: (MonadError ServantErr m) => Text -> m a
throwForbidden = throwError . authErrorServant . InsufficientScope

-- | Throw a unauthorized or forbidden error depending on the whther the claimes are 'Nothing' or 'Just'.
-- For use in endpoints using 'AuthOptional'.
throwForbiddenOrLogin :: (FromJWT auth, MonadError ServantErr m) => Maybe auth -> Text -> m a
throwForbiddenOrLogin (Just _) = throwForbidden
throwForbiddenOrLogin Nothing = throwError . authErrorServant . AuthRequired
