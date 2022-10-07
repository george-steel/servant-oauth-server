{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Servant.OAuth.Grants.OpenId where

import Data.Aeson
import Data.Text (Text)
import Web.HttpApiData

newtype OIDCSub = OIDCSub Text deriving (Eq, Ord, Read, Show, ToJSON, FromJSON, ToHttpApiData, FromHttpApiData)

data OIDCClaims = OIDCClaims
  { oidc_sub :: OIDCSub,
    oidc_email :: Maybe Text,
    oidc_name :: Maybe Text
  }
