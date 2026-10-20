---
title: The providers
order: 3
---

# The providers

A provider (`Provider\Provider`) gives the authorization address for an `Authorization` (state,
verifier, nonce) and, for the code that came back, the `Identity` it vouches for - or throws a
`ProviderError` with a stable reason. Its return address is its configuration's, never a request's.

## Google

```php
new GoogleProvider(
    clientId: '…apps.googleusercontent.com',
    clientSecret: '…',
    redirectUri: 'https://example.org/login/google/callback',   // lesringostars' oauth_google_check
    scopes: ['openid', 'email', 'profile'],                      // the default; openid is always there
    hostedDomain: null,                                          // a Workspace domain, or '*' for any
);
```

Over league/oauth2-google: the address on `accounts.google.com/o/oauth2/v2/auth` with the state,
the S256 challenge, the nonce and the scopes; the code posted to `oauth2.googleapis.com/token`
with the verifier. The person is read from the **ID token** the exchange returns, its claims
checked: issuer `https://accounts.google.com` (or `accounts.google.com`), audience this client
(and `azp` this client when there are several audiences), not past `exp` (60 seconds of leeway),
not issued in the future, the trip's nonce, and `hd` when a hosted domain is set. The token comes
straight from Google's token endpoint over TLS, so its signature is not checked (OpenID Connect
Core §3.1.3.7, point 6, lets the TLS server validation stand in for it here); no key set is
fetched. With no ID token, or one without the address, the userinfo endpoint is read through the
access token, and its subject must be the token's.

`email_verified` decides whether an address may link an account: `true` (or the string `"true"`
Google once sent) only.

## Another provider, by configuration (QA7)

Marco's decision: Google alone today; another one is added by its configuration the day it has
credentials. `Providers::fromConfig()` reads the same tree a host's `omniauth.yaml` (or
`config/omniauth.php`) holds:

```php
Providers::fromConfig([
    'google' => ['client_id' => $id, 'client_secret' => $secret, 'redirect_uri' => 'https://example.org/login/google/callback'],
    'facebook' => [
        'class' => League\OAuth2\Client\Provider\Facebook::class,   // composer require league/oauth2-facebook
        'client_id' => '', 'client_secret' => '', 'redirect_uri' => 'https://example.org/connect/facebook-check',
        'options' => ['graphApiVersion' => 'v19.0'],
        'scopes' => ['email', 'public_profile'],
        'fields' => ['subject' => 'id', 'email' => 'email', 'verified' => null, 'name' => 'name'],
    ],
    'gitea' => [   // league's GenericProvider, on the provider's three addresses
        'client_id' => '…', 'client_secret' => '…', 'redirect_uri' => 'https://example.org/connect/gitea-check',
        'authorize_url' => 'https://git.example/login/oauth/authorize',
        'token_url' => 'https://git.example/login/oauth/access_token',
        'userinfo_url' => 'https://git.example/api/v1/user',
    ],
]);
```

An entry without a `client_id` is not served (lesringostars declares six providers with no
credentials: they stay out). Any league/oauth2-client provider serves through `LeagueProvider`:
omniauth's state and PKCE in the address, the code exchanged with the verifier, the person read
from the resource owner's details; `fields` names their keys. A provider that says nothing of the
address (`verified: null`) never vouches for it: no account is linked by its address, only by its
subject. Leave the league provider's own `pkceMethod` unset: omniauth draws the verifier and keeps
it in the attempt (a league provider that draws its own is refused).

## In tests

`Testing\FakeProvider` is an authorization server in memory: `consent($authorizationUrl, $person)`
gives the return's `code` and `state`, `deny()` an `access_denied`; `identify()` exchanges a code
once, only with the verifier whose challenge the address carried, and checks the nonce. Under it a
host's tests sign in with no network, and a forged or injected return fails as it would at Google.
