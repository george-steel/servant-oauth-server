{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module: Servant.OAuth.ResourceServer
-- Description: JWT bearer token API combinators
-- Copyright: © 2018-2019 Satsuma labs, 2019-2021 George Steel
--
-- This module defines Servant API combinators which check or require OAuth2 bearer token authorization for use in resource servers.
-- Access tokens are assumed to be self-encoded using JWT, with no particular structure assumed about identity/authorization claims.
-- Claim types should implement the 'FromJWT' typeclass.
module Servant.OAuth.ResourceServer
  ( AuthRequired,
    AuthOptional,
    AuthError (..),
    module Servant.OAuth.JWT,
    authErrorServant,
    throwForbidden,
    throwForbiddenOrLogin,
  )
where

import Control.Monad.Except
import qualified Data.ByteString.Lazy as BL
import Data.Proxy
import Data.Text (Text, pack)
import qualified Data.Text.Encoding as T
import Network.Wai (Request, requestHeaders)
import Servant.API
import Servant.OAuth.JWT
import Servant.OAuth.ResourceServer.Types
import Servant.Server
import Servant.Server.Internal

instance (HasServer api context, HasContextEntry context JWTSettings, FromJWT claim) => HasServer (AuthRequired claim :> api) context where
  type ServerT (AuthRequired claim :> api) m = claim -> ServerT api m

  route ::
    ( HasServer api context,
      HasContextEntry context JWTSettings,
      FromJWT claim
    ) =>
    Proxy (AuthRequired claim :> api) ->
    Context context ->
    Delayed env (Server (AuthRequired claim :> api)) ->
    Router env
  route _ context subserver = route (Proxy @api) context (addAuthCheck subserver authCheck)
    where
      authCheck = withRequest $ requireLogin <=< checkJwtLogin (getContextEntry context)
      requireLogin = maybe (delayedFailFatal . authErrorServant $ AuthRequired "Login Required") return

  hoistServerWithContext ::
    ( HasServer api context,
      HasContextEntry context JWTSettings,
      FromJWT claim
    ) =>
    Proxy (AuthRequired claim :> api) ->
    Proxy context ->
    (forall x. m x -> n x) ->
    ServerT (AuthRequired claim :> api) m ->
    ServerT (AuthRequired claim :> api) n
  hoistServerWithContext _ pc f s = hoistServerWithContext (Proxy :: Proxy api) pc f . s

instance (HasServer api context, HasContextEntry context JWTSettings, FromJWT claim) => HasServer (AuthOptional claim :> api) context where
  type ServerT (AuthOptional claim :> api) m = Maybe claim -> ServerT api m

  route ::
    ( HasServer api context,
      HasContextEntry context JWTSettings,
      FromJWT claim
    ) =>
    Proxy (AuthOptional claim :> api) ->
    Context context ->
    Delayed env (Server (AuthOptional claim :> api)) ->
    Router env
  route Proxy context subserver = route (Proxy :: Proxy api) context (addAuthCheck subserver authCheck)
    where
      authCheck = withRequest $ checkJwtLogin (getContextEntry context)

  hoistServerWithContext ::
    ( HasServer api context,
      HasContextEntry context JWTSettings,
      FromJWT claim
    ) =>
    Proxy (AuthOptional claim :> api) ->
    Proxy context ->
    (forall x. m x -> n x) ->
    ServerT (AuthOptional claim :> api) m ->
    ServerT (AuthOptional claim :> api) n
  hoistServerWithContext _ pc f s = hoistServerWithContext (Proxy :: Proxy api) pc f . s

-- | Authorization check returning the correct error messages.
checkJwtLogin :: (FromJWT a) => JWTSettings -> Request -> DelayedIO (Maybe a)
checkJwtLogin settings req = case lookup "Authorization" (requestHeaders req) of
  Nothing -> return Nothing
  Just hdr -> do
    tok <- case parseHeader hdr of
      Left msg -> delayedFailFatal . authErrorServant $ InvalidAuthRequest msg
      Right t -> return t
    mauth <- liftIO $ checkAuthToken settings tok
    case mauth of
      Left err -> delayedFailFatal . authErrorServant . InvalidToken . pack . show $ err
      Right auth -> return (Just auth)

-- | Convert an authorization error into a 'ServantErr' with correct response code and body
authErrorServant :: AuthError -> ServerError
authErrorServant (AuthRequired msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidAuthRequest msg) = err400 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_request\"")], errBody = "Malformed authorization header: " <> BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InvalidToken msg) = err401 {errHeaders = [("WWW-Authenticate", "Bearer error=\"invalid_token\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}
authErrorServant (InsufficientScope msg) = err403 {errHeaders = [("WWW-Authenticate", "Bearer error=\"insufficient_scope\"")], errBody = BL.fromStrict (T.encodeUtf8 msg)}

-- | Throw an insufficient scope (403) error with a given message.
throwForbidden :: (MonadError ServerError m) => Text -> m a
throwForbidden = throwError . authErrorServant . InsufficientScope

-- | Throw a unauthorized or forbidden error depending on the whether the claims are 'Nothing' or 'Just'.
-- For use in endpoints using 'AuthOptional'.
throwForbiddenOrLogin :: (MonadError ServerError m) => Maybe auth -> Text -> m a
throwForbiddenOrLogin (Just _) = throwForbidden
throwForbiddenOrLogin Nothing = throwError . authErrorServant . AuthRequired
