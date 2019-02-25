{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, LambdaCase #-}

{-|
Module: Servant.OAuth.Server.TokenEndpoint
Description: OAuth2 token endpoint
Copyright: © 2018-2019 Satsuma labs, 2019 George Steel

This module defines Servant API endpoints implementing an OAuth2 token endpoint.
This does not assume any specific king of user store:
both endpoint implementations wrap an action validating a grant to return a set of claims.

-}

module Servant.OAuth.Server.TokenEndpoint where

import Crypto.JWT
import Servant.API
import Servant.Server

import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Applicative
import Control.Lens
import Data.Aeson
import Data.Time

import Servant.OAuth.Server
import Servant.OAuth.Grants

default(Text)


-- | Class for datatypes can be added as claims to a JWT
class (ToJWTClaims a) where
    -- | Modifies a 'ClaimsSet' to include the given claim
    consClaims :: a -> ClaimsSet -> ClaimsSet

instance (ToJWTClaims a, ToJWTClaims b) => ToJWTClaims (a,b) where
    consClaims (x,y) = consClaims y . consClaims x

instance (ToJWTClaims a) => ToJWTClaims (Maybe a) where
    consClaims (Just x) = consClaims x
    consClaims Nothing = id


-- | Signing settings for JWT creation.
-- Includes signing key, initial claims (which should include iss and aud if those do not vary per-token), and duration (from whoch iat and exp are computed).
data JWTSignSettings = JWTSignSettings {
    jwtSignKey :: JWK,
    jwtInitialClaims :: ClaimsSet,
    jwtDuration :: NominalDiffTime}

-- | API type of an OAuth2 token endpoint.
-- The grant type parameter should be a sum type built from the grant types, in "Servant.OAuth.Grants" with parsers combined using '<|>'.
-- 'Lenient' body handling is required to provide the correct error message format, which is handled by the endpoint implementations in this module.
type OAuthTokenEndpoint grant =
    ReqBody' '[Required,Lenient] '[FormUrlEncoded, JSON] grant :> Post '[JSON] OAuthTokenSuccess


-- | Token endpoint which does not issue refresh tokens.
-- Takes in token signing settings and an action to verify grants and convert them to token claims,
-- which should throw an error (using 'throwInvalidGrant') in the event of an invalid grant.
tokenEndpointNoRefresh :: forall m grant claims. (MonadIO m, MonadError ServantErr m, ToJWTClaims claims) =>
    JWTSignSettings -> (grant -> m claims) -> ServerT (OAuthTokenEndpoint grant) m
tokenEndpointNoRefresh signSettings doAuth = \case
    Left _ -> throwServantErrJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
    Right grant -> do
        claims <- doAuth grant
        tok <- liftIO $ makeAccessToken signSettings claims
        return $ OAuthTokenSuccess tok (jwtDuration signSettings) Nothing

-- | Token endpoint with refresh tokens.
-- Takes signing settings, an action to create and store a refresh token, and an action to validate grants and return claims.
-- The validation actuon must also return a Bool indicating whether a refresh token is to be created.
tokenEndpointWithRefresh  :: forall m grant claims. (MonadIO m, MonadError ServantErr m, ToJWTClaims claims) =>
    JWTSignSettings -> (claims -> m RefreshToken) -> (grant -> m (claims, Bool)) -> ServerT (OAuthTokenEndpoint grant) m
tokenEndpointWithRefresh signSettings makeRefresh doAuth = \case
    Left _ -> throwServantErrJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
    Right grant -> do
        (claims, shouldRefresh) <- doAuth grant
        rtok <- if shouldRefresh
            then fmap Just (makeRefresh claims)
            else return Nothing
        tok <- liftIO $ makeAccessToken signSettings claims
        return $ OAuthTokenSuccess tok (jwtDuration signSettings) rtok

-- | Throws a 'ServantErr' with a JSON formatted body.
throwServantErrJSON :: (MonadError ServantErr m, ToJSON v) => ServantErr -> v -> m a
throwServantErrJSON err val = throwError $ err {errHeaders = [("Content-Type", "application/json")], errBody = encode val}

-- | Throws an 'OAuthFailure' response indicating an invalid grant (status code 401).
throwInvalidGrant :: (MonadError ServantErr m) => Text -> m a
throwInvalidGrant msg = throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just msg) Nothing

-- | Creates a JWT from User entity and a signing key valid for a given length of time.
makeAccessToken :: (ToJWTClaims a) => JWTSignSettings -> a -> IO CompactJWT
makeAccessToken settings x = do
    now <- getCurrentTime
    let claimsSet = jwtInitialClaims settings
            & claimExp ?~ NumericDate (addUTCTime (jwtDuration settings) now)
            & claimIat ?~ NumericDate now
            & consClaims x
        Just (JWSAlg kalg) = jwtSignKey settings ^. jwkAlg -- requires valid key
        hdr = newJWSHeader ((), kalg) & kid .~ fmap (HeaderParam ()) (jwtSignKey settings ^. jwkKid)
    mtok <- runExceptT $ signClaims (jwtSignKey settings) hdr claimsSet
    let tok = case mtok of
            Right t -> t
            Left (err :: Error)  -> error (show err)
    return . CompactJWT . T.decodeUtf8 . BL.toStrict . encodeCompact $ tok
