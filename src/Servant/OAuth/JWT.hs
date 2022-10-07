{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Servant.OAuth.JWT
  ( -- * Tokens
    FromJWT (..),
    ToJWT (..),
    ClaimSub (..),

    -- * Verification
    CompactJWT (..),
    SomeJWKResolver (..),
    JWTSettings,
    checkAuthToken,

    -- * Signing
    JWTSignSettings (..),
    mkTestJWTSignSettings,
    makeAccessToken,
  )
where

import Control.Lens
import Control.Monad.Except
  ( ExceptT,
    MonadError (throwError),
    runExceptT,
  )
import Control.Monad.IO.Class
import Crypto.JOSE.JWA.JWK (Crv (P_256))
import Crypto.JOSE.JWK
import Crypto.JWT
  ( ClaimsSet,
    Error,
    HasKid (kid),
    HeaderParam (HeaderParam),
    JWK,
    JWKAlg (JWSAlg),
    JWSHeader,
    JWTError (JWTClaimsSetDecodeError),
    JWTValidationSettings,
    NumericDate (NumericDate),
    VerificationKeyStore,
    claimExp,
    claimIat,
    claimSub,
    decodeCompact,
    emptyClaimsSet,
    encodeCompact,
    jwkAlg,
    jwkKid,
    newJWSHeader,
    signClaims,
    string,
    verifyClaims,
  )
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text, unpack)
import qualified Data.Text.Encoding as T
import Data.Time
import Servant.OAuth.ResourceServer.Types
import Web.HttpApiData

-- | Types which can be read from a JWT
class FromJWT a where
  fromJWT :: ClaimsSet -> Either Text a

-- | Parses both claims in the pair.
instance (FromJWT a, FromJWT b) => FromJWT (a, b) where
  fromJWT claims = (,) <$> fromJWT claims <*> fromJWT claims

-- | Makes a claim optional. Parsing always succeeds: errors in the wrapped claim result in a 'Nothing' value.
instance (FromJWT a) => FromJWT (Maybe a) where
  fromJWT claims = either (const (Right Nothing)) (Right . Just) (fromJWT claims)

-- | Claims which can be added to a JWT prior to signing.
class FromJWT a => ToJWT a where
  -- | Modifies a 'ClaimsSet' to include the given claim
  consClaims :: a -> ClaimsSet -> ClaimsSet

instance (ToJWT a, ToJWT b) => ToJWT (a, b) where
  consClaims (x, y) = consClaims y . consClaims x

instance (ToJWT a) => ToJWT (Maybe a) where
  consClaims (Just x) = consClaims x
  consClaims Nothing = id

-- | Newtype for `sub` claims. Use with DerivingVia for FromJWT and ToJWT instances.
newtype ClaimSub a = ClaimSub a deriving (Eq, Ord, Show)

instance (FromHttpApiData a) => FromJWT (ClaimSub a) where
  fromJWT claims =
    fmap ClaimSub . parseQueryParam
      =<< maybe (Left "'sub' claim not found") Right (claims ^? claimSub . _Just . string)

instance (FromHttpApiData a, ToHttpApiData a) => ToJWT (ClaimSub a) where
  consClaims (ClaimSub x) = claimSub ?~ review string (toQueryParam x)

-- | Existential type for a source of token verification keys.
-- Usually this will just wrap a 'JWKSet' but other types are possible
-- (such as an action to fetch the public keys from an authorization server).
data SomeJWKResolver where
  SomeJWKResolver :: (VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) ClaimsSet k) => k -> SomeJWKResolver

-- | JWT verification settings to put into the servant context.
-- the validation settings must include a check of the @aud@ claim and should include a check of the @iss@ claim.
data JWTSettings = JWTSettings SomeJWKResolver JWTValidationSettings

-- | Checks a JWT for validity and returns the required claims.
checkAuthToken :: (FromJWT a) => JWTSettings -> CompactJWT -> IO (Either JWTError a)
checkAuthToken (JWTSettings (SomeJWKResolver keys) valsettings) (CompactJWT ctok) = runExceptT $ do
  tok <- decodeCompact . BL.fromStrict . T.encodeUtf8 $ ctok
  claims <- verifyClaims valsettings keys tok
  let mx = fromJWT claims
  either (throwError . JWTClaimsSetDecodeError . unpack) return mx

-- | Signing settings for JWT creation.
-- Includes signing key, initial claims (which should include iss and aud if those do not vary per-token), and duration (from which iat and exp are computed).
data JWTSignSettings = JWTSignSettings
  { jwtSignKey :: JWK,
    jwtInitialClaims :: ClaimsSet,
    jwtDuration :: NominalDiffTime
  }

-- | Generate a simple set of crypto credentials for a token server.  Get familiar with `jose`
-- if you want a `JWTSignSettings` that is ready for production.
mkTestJWTSignSettings :: MonadIO m => m JWTSignSettings
mkTestJWTSignSettings =
  JWTSignSettings
    <$> liftIO (genJWK (ECGenParam P_256))
    <*> pure emptyClaimsSet
    <*> pure 5

-- | Creates a JWT from User entity and a signing key valid for a given length of time.
-- The JWK in the settings must be a valid signing key.
makeAccessToken :: (ToJWT a) => JWTSignSettings -> a -> IO CompactJWT
makeAccessToken settings x = do
  now <- getCurrentTime
  let cset =
        jwtInitialClaims settings
          & claimExp ?~ NumericDate (addUTCTime (jwtDuration settings) now)
          & claimIat ?~ NumericDate now
          & consClaims x
      Just (JWSAlg kalg) = jwtSignKey settings ^. jwkAlg -- requires valid key
      hdr = newJWSHeader ((), kalg) & kid .~ fmap (HeaderParam ()) (jwtSignKey settings ^. jwkKid)
  Right tok <- runExceptT @Error $ signClaims (jwtSignKey settings) hdr cset
  return . CompactJWT . T.decodeUtf8 . BL.toStrict . encodeCompact $ tok
