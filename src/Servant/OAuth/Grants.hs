{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, OverloadedLists #-}
module Servant.OAuth.Grants where


import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import Control.Arrow
--import Control.Lens
import Data.Proxy
import Web.HttpApiData
import Web.FormUrlEncoded
import Data.Aeson
import Data.Maybe
import Data.Time
import GHC.TypeLits

default(Text)

param :: (ToHttpApiData a) => Text -> a -> Form
param k x = Form (H.singleton k [toQueryParam x])


newtype CompactJWT = CompactJWT Text deriving (Eq, Show, FromJSON, ToJSON)

instance (FromHttpApiData CompactJWT) where
    parseQueryParam = Right . CompactJWT
    parseHeader h = ((pack . show) +++ CompactJWT) . T.decodeUtf8' . fromMaybe h $ B.stripPrefix "Bearer " h

instance (ToHttpApiData CompactJWT) where
    toQueryParam (CompactJWT t) = t
    toHeader (CompactJWT t) = "Bearer " <> T.encodeUtf8 t

newtype RefreshToken = RefreshToken Text
    deriving (Ord, Eq, Read, Show, ToHttpApiData, FromHttpApiData, ToJSON, FromJSON)



data OAuthTokenSuccess = OAuthTokenSuccess {
    oauth_access_token :: CompactJWT,
    oauth_expires_in :: NominalDiffTime,
    oauth_refresh_token :: Maybe RefreshToken}
    deriving (Eq, Show)

instance ToJSON OAuthTokenSuccess where
    toJSON (OAuthTokenSuccess tok expt mrtok) = Object $
        "access_token" .= tok <> "expires_in" .= expt <> maybe mempty ("refresh_token" .=) mrtok

data OAuthErrorCode =
    InvalidGrantRequest
    | InvalidClient
    | InvalidGrant
    | InvalidScope
    | UnauthorizedClient
    | UnsupportedGrantType
    | InvalidTarget
    deriving (Eq, Read, Show)

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

instance ToJSON OAuthFailure where
    toJSON (OAuthFailure err mdesc muri) = Object $
        "error" .= err <> maybe mempty ("error_description" .=) mdesc <> maybe mempty ("error_uri" .=) muri


data OAuthGrantPassword = OAuthGrantPassword {
    gpw_username :: Text,
    gpw_password :: Text }
    deriving (Eq)

newtype OAuthGrantOpaqueAssertion (grant_type :: Symbol) = OAuthGrantOpaqueAssertion Text

newtype OAuthGrantJWTAssertion = OAuthGrantJWTAssertion CompactJWT

data OAuthGrantCodePKCE = OAuthGrantCodePKCE {
    gcp_code :: Text,
    gcp_code_verifier :: Text
}

newtype OAuthGrantRefresh = OAuthGrantRefresh RefreshToken

data WithScope s a = WithScope (Maybe s) a


instance FromJSON OAuthGrantPassword where
    parseJSON = withObject "password" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "password"
            then OAuthGrantPassword <$> o .: "username" <*> o .: "password"
            else fail "wrong grant type"

instance (KnownSymbol gt) => FromJSON (OAuthGrantOpaqueAssertion gt) where
    parseJSON = withObject ("assert_opaque:" <> symbolVal (Proxy @gt)) $ \o ->
        o .: "grant_type" >>= \pgt ->
            if pgt == (symbolVal (Proxy @gt))
            then OAuthGrantOpaqueAssertion <$> o .: "assertion"
            else fail "wrong grant type"

instance FromJSON OAuthGrantJWTAssertion where
    parseJSON = withObject "assert_jwt" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
            then OAuthGrantJWTAssertion <$> o .: "assertion"
            else fail "wrong grant type"

instance FromJSON OAuthGrantCodePKCE where
    parseJSON = withObject "code_pkce" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "authorization_code"
            then OAuthGrantCodePKCE <$> o .: "code" <*> o .: "code_verifier"
            else fail "wrong grant type"

instance FromJSON OAuthGrantRefresh where
    parseJSON = withObject "assert_jwt" $ \o ->
        o .: "grant_type" >>= \gt ->
            if gt == "refresh_token"
            then OAuthGrantRefresh <$> o .: "refresh_token"
            else fail "wrong grant type"

instance (FromJSON s, FromJSON a) => FromJSON (WithScope s a) where
    parseJSON v@(Object o) = WithScope <$> o .:? "scope" <*> parseJSON v
    parseJSON v = WithScope Nothing <$> parseJSON v


instance ToJSON OAuthGrantPassword where
    toJSON (OAuthGrantPassword un pw) = object ["grant_type" .= "password", "username" .= un, "password" .= pw]

instance (KnownSymbol gt) => ToJSON (OAuthGrantOpaqueAssertion gt) where
    toJSON (OAuthGrantOpaqueAssertion x) = object ["grant_type" .= symbolVal (Proxy @gt), "assertion" .= x]

instance ToJSON OAuthGrantJWTAssertion where
    toJSON (OAuthGrantJWTAssertion x) = object ["grant_type" .= "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" .= x]

instance ToJSON OAuthGrantCodePKCE where
    toJSON (OAuthGrantCodePKCE code ver) = object ["grant_type" .= "authorization_code", "code" .= code, "code_verifier" .= ver]

instance ToJSON OAuthGrantRefresh where
    toJSON (OAuthGrantRefresh x) = object ["grant_type" .= "refresh_token", "refresh_token" .= x]

instance (ToJSON s, ToJSON a) => ToJSON (WithScope s a) where
    toJSON (WithScope Nothing x) = toJSON x
    toJSON (WithScope (Just s) x) = let Object o = toJSON x in Object (H.insert "scope" (toJSON x) o)


instance FromForm OAuthGrantPassword where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "password"
        then OAuthGrantPassword <$> parseUnique "username" f <*> parseUnique "password" f
        else fail "wrong grant type"

instance (KnownSymbol gt) => FromForm (OAuthGrantOpaqueAssertion gt) where
    fromForm f = parseUnique "grant_type" f >>= \pgt ->
        if pgt == (symbolVal (Proxy @gt))
        then OAuthGrantOpaqueAssertion <$> parseUnique "assertion" f
        else fail "wrong grant type"

instance FromForm OAuthGrantJWTAssertion where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        then OAuthGrantJWTAssertion <$> parseUnique "assertion" f
        else fail "wrong grant type"

instance FromForm OAuthGrantCodePKCE where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "authorization_code"
        then OAuthGrantCodePKCE <$> parseUnique "code" f <*> parseUnique "code_verifier" f
        else fail "wrong grant type"

instance FromForm OAuthGrantRefresh where
    fromForm f = lookupUnique "grant_type" f >>= \gt ->
        if gt == "refresh_token"
        then OAuthGrantRefresh <$> parseUnique "refresh_token" f
        else fail "wrong grant type"

instance (FromHttpApiData s, FromForm a) => FromForm (WithScope s a) where
    fromForm f = WithScope <$> parseMaybe "scope" f <*> fromForm f


instance ToForm OAuthGrantPassword where
    toForm (OAuthGrantPassword un pw) = param "grant_type" "password" <> param "username" un <> param "password" pw

instance (KnownSymbol gt) => ToForm (OAuthGrantOpaqueAssertion gt) where
    toForm (OAuthGrantOpaqueAssertion x) = param "grant_type" (symbolVal (Proxy @gt)) <> param "assertion" x

instance ToForm OAuthGrantJWTAssertion where
    toForm (OAuthGrantJWTAssertion x) = param "grant_type" "urn:ietf:params:oauth:grant-type:jwt-bearer" <> param "assertion" x

instance ToForm OAuthGrantCodePKCE where
    toForm (OAuthGrantCodePKCE code ver) = param "grant_type" "authorization_code" <> param "code" code <> param "code_verifier" ver

instance ToForm OAuthGrantRefresh where
    toForm (OAuthGrantRefresh x) = param "grant_type" "refresh_token" <> param "refresh_token" x

instance (ToHttpApiData s, ToForm a) => ToForm (WithScope s a) where
    toForm (WithScope s x) = maybe mempty (param "scope") s <> toForm x
