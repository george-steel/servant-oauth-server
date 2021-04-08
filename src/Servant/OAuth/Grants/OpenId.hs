{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, LambdaCase, TemplateHaskell #-}
module Servant.OAuth.Grants.OpenId where

import Data.Text (Text, unpack, pack)
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Exception
import Web.HttpApiData
import Data.Aeson
import Data.Aeson.TH
import Data.Time
import Data.Time.Clock.POSIX

import Network.HTTP.Client
import Servant.OAuth.Grants

newtype OIDCSub = OIDCSub Text deriving (Eq, Ord, Read, Show, ToJSON, FromJSON, ToHttpApiData, FromHttpApiData)

data OIDCClaims = OIDCClaims {
    oidc_sub :: OIDCSub,
    oidc_email :: Maybe Text,
    oidc_name :: Maybe Text
}
