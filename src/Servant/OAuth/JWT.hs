{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

-- TODO: how much of this should live in `jose`?
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
    MakeAccessTokenError (..),
    AsMakeAccessTokenError (..),
  )
where

import Control.Lens
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except
  ( ExceptT,
    MonadError (throwError),
    runExceptT,
  )
import Control.Monad.IO.Class
import Crypto.JOSE.JWK
import Crypto.JWT
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Lazy.Char8 (ByteString)
import Data.String.Conversions (cs)
import Data.Text (Text, unpack)
import qualified Data.Text.Encoding as T
import Data.Text.Strict.Lens (utf8)
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
  deriving (Eq, Show)

-- | Generate a simple set of crypto credentials for a token server.  Get familiar with `jose`
-- if you want a `JWTSignSettings` that is ready for production.  Start with
-- `hs-jose/example/Main.hs`.
mkTestJWTSignSettings :: MonadIO m => m JWTSignSettings
mkTestJWTSignSettings =
  JWTSignSettings
    <$> liftIO (tweak <$> genJWK (OKPGenParam Ed25519))
    <*> pure emptyClaimsSet
    <*> pure 5
  where
    tweak k = f k
      where
        f = (jwkUse ?~ Sig) . (jwkKeyOps ?~ [Sign, Verify]) . (jwkKid ?~ kid')
        -- FUTUREWORK: _jwkAlg = Nothing, _jwkX5u = Nothing, _jwkX5cRaw = Nothing, _jwkX5t = Nothing, _jwkX5tS256 = Nothing
        -- (https://www.rfc-editor.org/rfc/rfc7517#section-4)
        h = view thumbprint k :: Digest SHA256
        kid' = view (re (base64url . digest) . utf8) h

-- | The error type of `makeAccessToken`.
--
-- TODO: we're creating classy prisms for this in the spirit of what `jose` does with `Error`,
-- but this is a bit messy and doesn't scale.  Some ideas:
--
-- (1) use `sop-core`-style open sum types for errors, which would require a lot of
-- refactoring here, and ideally in jose.
--
-- (2) use the `MonadIO` constraint in `makeAccessToken` to run `signClaims` from the `jose`
-- library, extract the error as an `Either` using `runExceptT`, and put everything back
-- together in the abstract return monad.  Or introduce a `newtype` for the monad we want to
-- run this in, which instantiates all the constraints for `signClaims`.  But it seems if we
-- run `signClaims` in *any* concrete monad here, we lose the abstract m that is concretized
-- elsewhere, and that has been given a concrete `MonadRandom` instance by the library user
-- for security reasons.
--
-- So (2) seems a non-solution; (1) may be worth pursuing at some point in the future.  For
-- now, we'll stick with the classy prisms mess.
data MakeAccessTokenError
  = MakeAccessTokenNoAlg ByteString
  | MakeAccessTokenEncNotSig ByteString
  | MakeAccessTokenJoseError Error
  deriving (Eq, Show)

makeClassyPrisms ''MakeAccessTokenError

instance AsError MakeAccessTokenError where
  _Error :: Prism' MakeAccessTokenError Error
  _Error = prism one two
    where
      one :: Error -> MakeAccessTokenError
      one = MakeAccessTokenJoseError

      two :: MakeAccessTokenError -> Either MakeAccessTokenError Error
      two = \case
        MakeAccessTokenJoseError err -> Right err
        other -> Left other

-- | Creates a JWT from User entity and a signing key valid for a given length of time.
-- The JWK in the settings must be a valid signing key.
makeAccessToken ::
  forall m e a.
  (MonadIO m, MonadRandom m, MonadError e m, AsError e, AsMakeAccessTokenError e, ToJWT a) =>
  JWTSignSettings ->
  a ->
  m CompactJWT
makeAccessToken settings x = do
  now <- liftIO getCurrentTime
  hdr <- do
    let thrw :: AReview e ByteString -> m x
        thrw cns = throwing cns (A.encode (jwtSignKey settings) <> "\n" <> cs (show settings))
    jwtSignKey settings ^. jwkAlg & \case
      Just (JWSAlg kalg) ->
        pure $ newJWSHeader ((), kalg) & kid .~ fmap (HeaderParam ()) (jwtSignKey settings ^. jwkKid)
      Just (JWEAlg _) -> thrw _MakeAccessTokenEncNotSig
      Nothing -> thrw _MakeAccessTokenNoAlg
  let cset =
        jwtInitialClaims settings
          & claimExp ?~ NumericDate (addUTCTime (jwtDuration settings) now)
          & claimIat ?~ NumericDate now
          & consClaims x
  tok <- signClaims (jwtSignKey settings) hdr cset
  return . CompactJWT . T.decodeUtf8 . BL.toStrict . encodeCompact $ tok
