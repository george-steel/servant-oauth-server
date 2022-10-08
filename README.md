# servant-oauth-server

This library consists of to main components: a Servant API combinator for bearer token authentication on resource servers,
and a token endpoint for authorization servers. Access tokens are self-encoded using JWT.
See haddocks for detailed API reference.

## Resource Servers

To protect an API and require a given claims set, use `AuthRequired claims :> api` which will require a valid token and capture its claims
(the endpoint will be a function from the claims to the wrapped endpoint, as with other parameters).
The required claims must implement `FromJWT`, which provides a default instance for `sub` claims.
For endpoints with mixed public and private content, use `AuthOptional` instead of `AuthRequired`,
which will also accept no authorization header (although an invalid token will still cause an error response) and capture `Nothing` if given such a request.
This is distinct from `AuthRequired (Maybe claims)`, which still requires a valid token but will accept one without any specific claims.

## Token Endpoint

The other part of this library is a set of functions for defining token endpoints,
with the aim of making the case of a backend for a first-party SPA or mobile app as simple as possible.
Creating a token endpoint requires a grant type and an action to verify those grants and return claims (or throw an error for invalid grants).
Standard grants (and their parsing instances) are defined in `Servant.OAuth.Grants`.
For endpoints which use a single type of grant, these can be used directly, or they used in a custom sum type, with parsers combined using `<|>`.

If refresh tokens are to be used, the validation action must also return a boolean indicating whether a refresh token is to be created with the request.
The endpoint wrapper must additionally be given an action to create and store an opaque refresh token, which must be recognized later by the validation action.

## How to understand this library

First, take a peak at https://www.rfc-editor.org/rfc/rfc7519 (JWTs)
and https://www.rfc-editor.org/rfc/rfc6749 (oauth2).  Then read the
test suite.  It implements some flows with all entities involved on
the level of wai `Application`s.
