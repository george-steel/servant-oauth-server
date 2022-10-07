{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module: Servant.OAuth.Grants
-- Description: OAuth2 grant and response types
-- Copyright: © 2018-2019 Satsuma labs, 2019 George Steel
--
-- This module data types and serialization instances for OAuth token requests and responses.
-- The serialization instances require/emit the correct @grant_type@ parameter and marsers may be combined using '(<|>)' for sum types.
-- (@sumEncoding = UntaggedValue@ may also be uused if using Aeson TH or Generic instances).
module Servant.OAuth.Grants where

import Control.Applicative
import Control.Arrow
import Data.Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import Data.Maybe
import Data.Proxy
import Data.Text (Text, pack, unpack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time
import GHC.TypeLits
import Servant.OAuth.ResourceServer.Types
import Servant.OAuth.TokenServer.Types
import Web.FormUrlEncoded
import Web.HttpApiData

default (Text)

-- | Created a 'Form' with a single parameter. Combine results using the 'Monoid' instance to create more complex 'Form's.
param :: (ToHttpApiData a) => Text -> a -> Form
param k x = Form (H.singleton k [toQueryParam x])

-- | Encode a 'Form' to a URL query string including the initial question mark.
qstring :: Form -> B.ByteString
qstring f = BL.toStrict $ "?" <> urlEncodeForm f

-- * Tokens

-- | Type for opaque access tokens. Header encoding includes @Bearer@ prefix.
newtype OpaqueToken = OpaqueToken Text deriving (Eq, Ord, Show, FromJSON, ToJSON)

instance (FromHttpApiData OpaqueToken) where
  parseQueryParam = Right . OpaqueToken
  parseHeader h = ((pack . show) +++ OpaqueToken) . T.decodeUtf8' . fromMaybe h $ B.stripPrefix "Bearer " h

instance (ToHttpApiData OpaqueToken) where
  toQueryParam (OpaqueToken t) = t
  toHeader (OpaqueToken t) = "Bearer " <> T.encodeUtf8 t

-- * Grants

-- | Client identifier for third party clients.
newtype OAuthClientId = OAuthClientId Text
  deriving (Ord, Eq, Read, Show, ToHttpApiData, FromHttpApiData, ToJSON, FromJSON)

-- | Resource owner credentials grant.
data OAuthGrantPassword = OAuthGrantPassword
  { gpw_username :: Text,
    gpw_password :: Text
  }
  deriving (Eq)

-- | Custom assertion grant parameterized by grant_type (which according to spec should be a URI).
-- Used for federated login with identity providers returning opaque tokens (such as Facebook).
newtype OAuthGrantOpaqueAssertion (grant_type :: Symbol) = OAuthGrantOpaqueAssertion OpaqueToken
  deriving (Eq, Show, FromHttpApiData, ToHttpApiData)

-- | JWT assertion grant. Use this for OpenID Connect @id_token@s.
newtype OAuthGrantJWTAssertion = OAuthGrantJWTAssertion CompactJWT

-- | Refresh token grant
newtype OAuthGrantRefresh = OAuthGrantRefresh RefreshToken

-- | Authorization code grant with PKCE verifier.
data OAuthGrantCodePKCE = OAuthGrantCodePKCE
  { gcp_code :: Text,
    gcp_code_verifier :: Text
  }

-- | Adds a scope restriction to a grant.
data WithScope s a = WithScope (Maybe s) a

instance FromJSON OAuthGrantPassword where
  parseJSON = withObject "password" $ \o ->
    o .: "grant_type" >>= \(gt :: Text) ->
      if gt == "password"
        then OAuthGrantPassword <$> o .: "username" <*> o .: "password"
        else fail "wrong grant type"

instance (KnownSymbol gt) => FromJSON (OAuthGrantOpaqueAssertion gt) where
  parseJSON = withObject ("assert_opaque:" <> symbolVal (Proxy @gt)) $ \o ->
    o .: "grant_type" >>= \(pgt :: String) ->
      if pgt == symbolVal (Proxy @gt)
        then OAuthGrantOpaqueAssertion <$> o .: "assertion"
        else fail "wrong grant type"

instance FromJSON OAuthGrantJWTAssertion where
  parseJSON = withObject "assert_jwt" $ \o ->
    o .: "grant_type" >>= \(gt :: Text) ->
      if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        then OAuthGrantJWTAssertion <$> o .: "assertion"
        else fail "wrong grant type"

instance FromJSON OAuthGrantCodePKCE where
  parseJSON = withObject "code_pkce" $ \o ->
    o .: "grant_type" >>= \(gt :: Text) ->
      if gt == "authorization_code"
        then OAuthGrantCodePKCE <$> o .: "code" <*> o .: "code_verifier"
        else fail "wrong grant type"

instance FromJSON OAuthGrantRefresh where
  parseJSON = withObject "assert_jwt" $ \o ->
    o .: "grant_type" >>= \(gt :: Text) ->
      if gt == "refresh_token"
        then OAuthGrantRefresh <$> o .: "refresh_token"
        else fail "wrong grant type"

instance (FromJSON s, FromJSON a) => FromJSON (WithScope s a) where
  parseJSON v@(Object o) = WithScope <$> o .:? "scope" <*> parseJSON v
  parseJSON v = WithScope Nothing <$> parseJSON v

instance ToJSON OAuthGrantPassword where
  toJSON (OAuthGrantPassword un pw) = object ["grant_type" .= ("password" :: Text), "username" .= un, "password" .= pw]

instance (KnownSymbol gt) => ToJSON (OAuthGrantOpaqueAssertion gt) where
  toJSON (OAuthGrantOpaqueAssertion x) = object ["grant_type" .= symbolVal (Proxy @gt), "assertion" .= x]

instance ToJSON OAuthGrantJWTAssertion where
  toJSON (OAuthGrantJWTAssertion x) = object ["grant_type" .= ("urn:ietf:params:oauth:grant-type:jwt-bearer" :: Text), "assertion" .= x]

instance ToJSON OAuthGrantCodePKCE where
  toJSON (OAuthGrantCodePKCE code ver) = object ["grant_type" .= ("authorization_code" :: Text), "code" .= code, "code_verifier" .= ver]

instance ToJSON OAuthGrantRefresh where
  toJSON (OAuthGrantRefresh x) = object ["grant_type" .= ("refresh_token" :: Text), "refresh_token" .= x]

instance (ToJSON s, ToJSON a) => ToJSON (WithScope s a) where
  toJSON (WithScope Nothing x) = toJSON x
  toJSON (WithScope (Just s) x) = let Object o = toJSON x in Object (KeyMap.insert "scope" (toJSON s) o)

instance FromForm OAuthGrantPassword where
  fromForm f =
    lookupUnique "grant_type" f >>= \gt ->
      if gt == "password"
        then OAuthGrantPassword <$> parseUnique "username" f <*> parseUnique "password" f
        else Left "wrong grant type"

instance (KnownSymbol gt) => FromForm (OAuthGrantOpaqueAssertion gt) where
  fromForm f =
    parseUnique "grant_type" f >>= \pgt ->
      if pgt == (symbolVal (Proxy @gt))
        then OAuthGrantOpaqueAssertion <$> parseUnique "assertion" f
        else Left "wrong grant type"

instance FromForm OAuthGrantJWTAssertion where
  fromForm f =
    lookupUnique "grant_type" f >>= \gt ->
      if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        then OAuthGrantJWTAssertion <$> parseUnique "assertion" f
        else Left "wrong grant type"

instance FromForm OAuthGrantCodePKCE where
  fromForm f =
    lookupUnique "grant_type" f >>= \gt ->
      if gt == "authorization_code"
        then OAuthGrantCodePKCE <$> parseUnique "code" f <*> parseUnique "code_verifier" f
        else Left "wrong grant type"

instance FromForm OAuthGrantRefresh where
  fromForm f =
    lookupUnique "grant_type" f >>= \gt ->
      if gt == "refresh_token"
        then OAuthGrantRefresh <$> parseUnique "refresh_token" f
        else Left "wrong grant type"

instance (FromHttpApiData s, FromForm a) => FromForm (WithScope s a) where
  fromForm f = WithScope <$> parseMaybe "scope" f <*> fromForm f

instance ToForm OAuthGrantPassword where
  toForm (OAuthGrantPassword un pw) = param "grant_type" ("password" :: Text) <> param "username" un <> param "password" pw

instance (KnownSymbol gt) => ToForm (OAuthGrantOpaqueAssertion gt) where
  toForm (OAuthGrantOpaqueAssertion x) = param "grant_type" (symbolVal (Proxy @gt)) <> param "assertion" x

instance ToForm OAuthGrantJWTAssertion where
  toForm (OAuthGrantJWTAssertion x) = param "grant_type" ("urn:ietf:params:oauth:grant-type:jwt-bearer" :: Text) <> param "assertion" x

instance ToForm OAuthGrantCodePKCE where
  toForm (OAuthGrantCodePKCE code ver) = param "grant_type" ("authorization_code" :: Text) <> param "code" code <> param "code_verifier" ver

instance ToForm OAuthGrantRefresh where
  toForm (OAuthGrantRefresh x) = param "grant_type" ("refresh_token" :: Text) <> param "refresh_token" x

instance (ToHttpApiData s, ToForm a) => ToForm (WithScope s a) where
  toForm (WithScope s x) = maybe mempty (param "scope") s <> toForm x
