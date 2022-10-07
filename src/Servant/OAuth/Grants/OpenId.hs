{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module Servant.OAuth.Grants.OpenId where

import Control.Exception
import Control.Monad.Except
import Control.Monad.IO.Class
import Data.Aeson
import Data.Aeson.TH
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text, pack, unpack)
import Data.Time
import Data.Time.Clock.POSIX
import Network.HTTP.Client
import Servant.OAuth.Grants
import Web.HttpApiData

newtype OIDCSub = OIDCSub Text deriving (Eq, Ord, Read, Show, ToJSON, FromJSON, ToHttpApiData, FromHttpApiData)

data OIDCClaims = OIDCClaims
  { oidc_sub :: OIDCSub,
    oidc_email :: Maybe Text,
    oidc_name :: Maybe Text
  }
