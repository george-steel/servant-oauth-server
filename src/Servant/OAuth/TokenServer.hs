{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Servant.OAuth.Server.TokenEndpoint
-- Description: OAuth2 token endpoint
-- Copyright: © 2018-2019 Satsuma labs, 2019 George Steel
--
-- This module defines Servant API endpoints implementing an OAuth2 token endpoint.
-- This does not assume any specific king of user store:
-- both endpoint implementations wrap an action validating a grant to return a set of claims.
module Servant.OAuth.TokenServer
  ( OAuthTokenSuccess (..),
    OAuthTokenEndpoint,
    JWTSignSettings (..),
    tokenEndpointNoRefresh,
    tokenEndpointWithRefresh,
    throwServerErrorJSON,
    throwInvalidGrant,
  )
where

import Control.Lens (prism)
import Control.Lens.Combinators (Prism')
import Control.Monad.Except
import Crypto.JOSE (AsError (_Error), Error)
import Crypto.JWT (MonadRandom)
import Data.Aeson
import Data.String.Conversions (cs)
import Data.Text (Text)
import Servant.OAuth.JWT
import Servant.OAuth.TokenServer.Types
import Servant.Server

-- | Token endpoint which does not issue refresh tokens.
-- Takes in token signing settings and an action to verify grants and convert them to token claims,
-- which should throw an error (using 'throwInvalidGrant') in the event of an invalid grant.
tokenEndpointNoRefresh ::
  forall m grant claims contentTypes.
  (MonadIO m, MonadRandom m, MonadError ServerError m, ToJWT claims) =>
  JWTSignSettings ->
  (grant -> m claims) ->
  ServerT (OAuthTokenEndpoint' contentTypes grant) m
tokenEndpointNoRefresh signSettings doAuth = \case
  Left _ -> throwServerErrorJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
  Right grant -> do
    claims <- doAuth grant
    tok <- makeAccessToken signSettings claims
    return $ OAuthTokenSuccess tok (jwtDuration signSettings) Nothing

instance AsError ServerError where
  _Error :: Prism' ServerError Error
  _Error = prism one two
    where
      one :: Error -> ServerError
      one err =
        ServerError
          { errHTTPCode = 400,
            errReasonPhrase = "could-not-sign-oauth-token",
            errBody = cs $ show err, -- TODO: json encode instead of show?  but missing instance.
            errHeaders = []
          }

      two :: ServerError -> Either ServerError Error
      two = Left -- TODO: this could use some more love.

-- | Token endpoint with refresh tokens.
-- Takes signing settings, an action to create and store a refresh token, and an action to validate grants and return claims.
-- The validation action must also return a Bool indicating whether a refresh token is to be created.
tokenEndpointWithRefresh ::
  forall m grant claims contentTypes.
  (MonadIO m, MonadRandom m, MonadError ServerError m, ToJWT claims) =>
  JWTSignSettings ->
  (claims -> m RefreshToken) ->
  (grant -> m (claims, Bool)) ->
  ServerT (OAuthTokenEndpoint' contentTypes grant) m
tokenEndpointWithRefresh signSettings makeRefresh doAuth = \case
  Left _ -> throwServerErrorJSON err400 $ OAuthFailure InvalidGrantRequest (Just "unable to parse token request") Nothing
  Right grant -> do
    (claims, shouldRefresh) <- doAuth grant
    rtok <-
      if shouldRefresh
        then fmap Just (makeRefresh claims)
        else return Nothing
    tok <- makeAccessToken signSettings claims
    return $ OAuthTokenSuccess tok (jwtDuration signSettings) rtok

-- | Throws a 'ServerError' with a JSON formatted body.
throwServerErrorJSON :: (MonadError ServerError m, ToJSON v) => ServerError -> v -> m a
throwServerErrorJSON err val = throwError $ err {errHeaders = [("Content-Type", "application/json")], errBody = encode val}

-- | Throws an 'OAuthFailure' response indicating an invalid grant (status code 401).
throwInvalidGrant :: (MonadError ServerError m) => Text -> m a
throwInvalidGrant msg = throwServerErrorJSON err401 $ OAuthFailure InvalidGrant (Just msg) Nothing
