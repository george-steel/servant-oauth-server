{-# LANGUAGE FlexibleContexts, FlexibleInstances, MultiParamTypeClasses, ScopedTypeVariables, GeneralizedNewtypeDeriving,
    GADTs, TypeFamilies, TypeApplications, DefaultSignatures, TypeOperators, DataKinds,
    OverloadedStrings, ExtendedDefaultRules, LambdaCase, TemplateHaskell #-}
module Servant.OAuth.Server.Facebook where

import Data.Text (Text, unpack, pack)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class
import Control.Monad.Except
import Control.Exception
import Control.Arrow
import Control.Lens
import Data.Proxy
import Web.HttpApiData
import Web.FormUrlEncoded (urlEncodeForm)
import Data.Aeson
import Data.Aeson.TH
import Data.Maybe
import GHC.TypeLits
import Data.Time
import Data.Time.Clock.POSIX

import Network.HTTP.Client
import Network.HTTP.Types
import Servant.Server.Internal.ServantErr

import Servant.OAuth.Server
import Servant.OAuth.Server.TokenEndpoint
import Servant.OAuth.Grants

type OAuthGrantFacebookAssertion = OAuthGrantOpaqueAssertion "https://graph.facebook.com/oauth/access_token"

newtype FacebookUserId = FacebookUserId Text deriving (Eq, Ord, Read, Show, ToJSON, FromJSON, ToHttpApiData, FromHttpApiData)


newtype FBData a = FBData {fb_data :: a} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 3}) ''FBData

data FacebookError = FacebookError {
    fberr_code :: Int,
    fberr_message :: Text
} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 6}) ''FacebookError

data FacebookTokenCheck = RecognisedToken {
    ftc_is_valid :: Bool,
    ftc_app_id :: OAuthClientId,
    ftc_user_id :: FacebookUserId,
    ftc_type :: Text,
    ftc_application :: Text,
    ftc_expires_at :: POSIXTime,
    ftc_scopes :: [Text],
    ftc_error :: Maybe FacebookError
} | BogusToken {
    ftc_is_valid :: Bool,
    ftc_error :: Maybe FacebookError
} deriving (Show)
deriveFromJSON (defaultOptions {fieldLabelModifier = drop 4, sumEncoding = UntaggedValue}) ''FacebookTokenCheck

data FacebookUserInfo = FacebookUserInfo {
    fb_id :: FacebookUserId,
    fb_name :: Text,
    fb_short_name :: Text,
    fb_email :: Maybe Text
} deriving (Show)
deriveJSON (defaultOptions {fieldLabelModifier = drop 3, sumEncoding = UntaggedValue}) ''FacebookUserInfo

data FacebookSettings = FacebookSettings {
    fbHttp :: Manager,
    fbAppId :: OAuthClientId,
    fbTokenProvider :: IO OpaqueToken
}

checkFacebookAssertion :: (MonadIO m, MonadError ServantErr m) => FacebookSettings -> OAuthGrantFacebookAssertion -> m (FacebookUserId, FacebookTokenCheck)
checkFacebookAssertion settings (OAuthGrantOpaqueAssertion tok) = do
    atok <- liftIO $ fbTokenProvider settings
    let req = (parseRequest_ "https://graph.facebook.com/debug_token") {
            queryString = qstring $ param "input_token" tok,
            requestHeaders = [("Authorization", toHeader atok),
                              ("Accept", "application/json")],
            checkResponse = throwErrorStatusCodes}
    mresp :: Either HttpException (Response BL.ByteString) <- liftIO . try $ httpLbs req (fbHttp settings)
    result <- case mresp of
        Left e -> do
            liftIO . putStrLn $ "Error checking facebook token: " ++ show e
            throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailabe (Just "Error contacting Facebook") Nothing
        Right resp -> case decode' (responseBody resp) of
            Nothing -> do
                liftIO . putStrLn $ "Error decoding facebook token check"
                throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailabe (Just "Error decoding facebook token check") Nothing
            Just (FBData x) -> return x
    uid <- case result of
        BogusToken {} -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Unrecognised Facebook token") Nothing
        RecognisedToken {ftc_is_valid = valid}
            | valid -> return (ftc_user_id result)
            | otherwise -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Invalid Facebook token") Nothing
    return (uid, result)

getFacebookRegistrationInfo :: (MonadIO m, MonadError ServantErr m) => FacebookSettings -> OAuthGrantFacebookAssertion -> m FacebookUserInfo
getFacebookRegistrationInfo settings (OAuthGrantOpaqueAssertion tok) = do
    let req = (parseRequest_ "https://graph.facebook.com/v3.2/me?fields=id,name,short_name,email") {
            requestHeaders = [("Authorization", toHeader tok), ("Accept", "application/json")]}
    mresp :: Either HttpException (Response BL.ByteString) <- liftIO . try $ httpLbs req (fbHttp settings)
    case mresp of
        Left _ -> throwServantErrJSON err502 $ OAuthFailure TemporarilyUnavailabe (Just "Error contacting Facebook") Nothing
        Right resp -> case decode' (responseBody resp) of
            Nothing -> throwServantErrJSON err401 $ OAuthFailure InvalidGrant (Just "Unable to fetch registration info") Nothing
            Just u -> return u
