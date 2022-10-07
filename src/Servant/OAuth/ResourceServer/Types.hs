{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Servant.OAuth.ResourceServer.Types where

import Control.Arrow ((+++))
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.ByteString as B
import Data.Maybe
import Data.Text (Text, pack)
import qualified Data.Text.Encoding as T
import Web.HttpApiData

-- * API combinators

-- | API combinator to require bearer token authorization, capturing the claims.
data AuthRequired claim

-- | API combinator which captures token claims but does not require a token.
-- The captured claims are wrapped in 'Maybe' to handle the anonymous case.
-- Use this for an endpoint with mixed public and private content (possibly depending on a parameter).
data AuthOptional claim

data AuthError
  = AuthRequired Text
  | InvalidAuthRequest Text
  | InvalidToken Text
  | InsufficientScope Text
  deriving (Eq, Read, Show)

-- | Reperesents a compact-encoded JWT access tokens token in requests and responses. Header encoding includes @Bearer@ prefix.
newtype CompactJWT = CompactJWT Text deriving (Eq, Show, FromJSON, ToJSON)

instance (FromHttpApiData CompactJWT) where
  parseQueryParam = Right . CompactJWT
  parseHeader h = ((pack . show) +++ CompactJWT) . T.decodeUtf8' . fromMaybe h $ B.stripPrefix "Bearer " h

instance (ToHttpApiData CompactJWT) where
  toQueryParam (CompactJWT t) = t
  toHeader (CompactJWT t) = "Bearer " <> T.encodeUtf8 t
