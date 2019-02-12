{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, LambdaCase #-}
module Servant.OAuth.Server.TokenEndpoint where

import Crypto.JWT
import Servant.API
import Servant.Server
import Servant.Server.Internal.ServantErr

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
import Web.HttpApiData
import Web.FormUrlEncoded
import Data.Aeson
import Data.Maybe
import GHC.TypeLits
import Data.Time

import Servant.OAuth.Server
import Servant.OAuth.Grants

default(Text)

class (ToJWTClaims a) where
    consClaims :: a -> ClaimsSet -> ClaimsSet

instance (ToJWTClaims a, ToJWTClaims b) => ToJWTClaims (a,b) where
    consClaims (x,y) = consClaims y . consClaims x

instance (ToJWTClaims a) => ToJWTClaims (Maybe a) where
    consClaims (Just x) = consClaims x
    consClaims Nothing = id


data JWTSignSettings = JWTSignSettings {
    jwtSignKey :: JWK,
    jwtInitialClaims :: ClaimsSet,
    jwtDuration :: NominalDiffTime}

type OAuthTokenEndpoint grant =
    ReqBody' '[Required,Lenient] '[FormUrlEncoded, JSON] grant :> Post '[JSON] OAuthTokenSuccess


-- | Creates a JWT from User entity and a signing key valid for a given length of time
-- Requires a valid key in signing settings
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

throwServantErrJSON :: (MonadError ServantErr m, ToJSON v) => ServantErr -> v -> m a
throwServantErrJSON err val = throwError $ err {errHeaders = [("Content-Type", "application/json")], errBody = encode val}

throwInvalidGrant :: (MonadError ServantErr m) => Text -> m a
throwInvalidGrant msg = throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just msg) Nothing

tokenEndpointNoRefresh :: forall m grant a. (MonadIO m, MonadError ServantErr m, ToJWTClaims a) =>
    JWTSignSettings -> (grant -> m a) -> ServerT (OAuthTokenEndpoint grant) m
tokenEndpointNoRefresh signSettings doAuth = \case
    Left _ -> throwServantErrJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
    Right grant -> do
        claims <- doAuth grant
        tok <- liftIO $ makeAccessToken signSettings claims
        return $ OAuthTokenSuccess tok (jwtDuration signSettings) Nothing

tokenEndpointWithRefresh  :: forall m grant a. (MonadIO m, MonadError ServantErr m, ToJWTClaims a) =>
    JWTSignSettings -> (a -> m RefreshToken) -> (grant -> m (a, Bool)) -> ServerT (OAuthTokenEndpoint grant) m
tokenEndpointWithRefresh signSettings makeRefresh doAuth = \case
    Left _ -> throwServantErrJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
    Right grant -> do
        (claims, shouldRefresh) <- doAuth grant
        rtok <- if shouldRefresh
            then fmap Just (makeRefresh claims)
            else return Nothing
        tok <- liftIO $ makeAccessToken signSettings claims
        return $ OAuthTokenSuccess tok (jwtDuration signSettings) rtok
