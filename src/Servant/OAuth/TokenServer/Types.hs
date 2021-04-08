{-# LANGUAGE GeneralizedNewtypeDeriving, OverloadedStrings, DataKinds, TypeOperators #-}

module Servant.OAuth.TokenServer.Types where

import Data.Text (Text, unpack, pack)
import qualified Data.Text as T

import Web.HttpApiData
import Web.FormUrlEncoded
import Data.Aeson
import Data.Time
import Servant

import Servant.OAuth.ResourceServer.Types


-- | Type for refresh tokens. These are always opaque and not used in Authorization headers.
newtype RefreshToken = RefreshToken Text
    deriving (Ord, Eq, Read, Show, ToHttpApiData, FromHttpApiData, ToJSON, FromJSON)


-- | Successful response type for OAuth token endpoints
data OAuthTokenSuccess = OAuthTokenSuccess {
    oauth_access_token :: CompactJWT,
    oauth_expires_in :: NominalDiffTime,
    oauth_refresh_token :: Maybe RefreshToken}
    deriving (Eq, Show)

instance ToJSON OAuthTokenSuccess where
    toJSON (OAuthTokenSuccess tok expt mrtok) = Object $
        "access_token" .= tok <> "expires_in" .= expt <> maybe mempty ("refresh_token" .=) mrtok
instance FromJSON OAuthTokenSuccess where
    parseJSON = withObject "OAuthTokenSuccess" $ \o -> OAuthTokenSuccess
        <$> o .: "access_token"
        <*> o .: "expires_in"
        <*> o .:? "refresh_token"

-- | OAuth error codes.
data OAuthErrorCode =
    InvalidGrantRequest
    | InvalidClient
    | InvalidGrant
    | InvalidScope
    | UnauthorizedClient
    | UnsupportedGrantType
    | InvalidTarget
    | TemporarilyUnavailable
    deriving (Eq, Read, Show)

-- | Failure response for OAuth token endpoints. Serialize this as the body of an error response.
data OAuthFailure = OAuthFailure {
    oauth_error :: OAuthErrorCode,
    oauth_error_description :: Maybe Text,
    oauth_error_uri :: Maybe Text}
    deriving (Eq, Read, Show)

instance ToJSON OAuthErrorCode where
    toJSON InvalidGrantRequest = String "invalid_request"
    toJSON InvalidClient = String "invalid_client"
    toJSON InvalidGrant = String "invalid_grant"
    toJSON InvalidScope = String "invalid_scope"
    toJSON UnauthorizedClient = String "unauthorized_client"
    toJSON UnsupportedGrantType = String "unsupported_grant_type"
    toJSON InvalidTarget = String "invalid_target"
    toJSON TemporarilyUnavailable = String "temporarily_unavailable"

instance ToJSON OAuthFailure where
    toJSON (OAuthFailure err mdesc muri) = Object $
        "error" .= err <> maybe mempty ("error_description" .=) mdesc <> maybe mempty ("error_uri" .=) muri


-- | API type of an OAuth2 token endpoint.
-- The grant type parameter should be a sum type built from the grant types, in "Servant.OAuth.Grants" with parsers combined using '<|>'.
-- 'Lenient' body handling is required to provide the correct error message format, which is handled by the endpoint implementations in this module.
type OAuthTokenEndpoint grant =
    ReqBody' '[Required,Lenient] '[FormUrlEncoded, JSON] grant :> Post '[JSON] OAuthTokenSuccess
