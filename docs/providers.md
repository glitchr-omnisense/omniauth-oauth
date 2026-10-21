---
title: The providers
order: 3
---

# The providers

A provider (`Provider\Provider`) gives the authorization address for an `Authorization` (state,
verifier, nonce, the origin the trip began at) and, for the code that came back, the `Identity` it
vouches for - or throws a `ProviderError` with a stable reason. This package has none that speaks
to a real server: **each provider is a package of its own** (Marco's decision, 2026-10-21, the shape
of omnishield's captchas) - [omniauth/google](https://github.com/glitchr-studio/omniauth-google)
first, over league/oauth2-google.

## The return address

A provider's return address is its configuration's, never a request's: an absolute address, or a
**path** (`/login/google/callback`). A path is completed by the origin of the request that began
the trip (`Authorization::returnAddress()`, the origin kept in the attempt with the state): a site
served on two hosts, or a long-running worker (FrankenPHP) that serves several, sends each visitor
back to the host they left from - never to the first host the worker served -, and the exchange
repeats that trip's address, as an authorization server compares them. Each address must be one of
the client's registered return addresses at the provider.

## By configuration

`Providers::configured()` reads the tree a host's `omniauth.yaml` (or `config/omniauth.php`) holds,
each entry made by the first factory (`Provider\ProviderFactory`) that knows its kind:

```php
Providers::configured([
    'google' => ['client_id' => $id, 'client_secret' => $secret, 'redirect_uri' => '/login/google/callback'],
], new Omniauth\Google\GoogleFactory());
```

An entry without a `client_id` is not served (lesringostars declares providers with no credentials:
they stay out); one without a `redirect_uri`, or that no factory makes, is a mistake
(`InvalidArgumentException`, naming the package to install). Providers given as they are (a
service) sit beside them: `new Providers($given, ...Providers::configured($config, ...$factories))`.

`Providers::fromConfig()` (deprecated, kept one release) makes its Google entries through
omniauth/google's factory when that package is installed; `Omniauth\OAuth\Provider\GoogleProvider`
and `LeagueProvider` are aliases of omniauth/google's classes for the same release.

## In tests

`Testing\FakeProvider` is an authorization server in memory: `consent($authorizationUrl, $person)`
gives the return's `code` and `state`, `deny()` an `access_denied`; `identify()` exchanges a code
once, only with the verifier whose challenge the address carried and for the return address it was
given to, and checks the nonce. Its return address may be a path too. Under it a host's tests sign
in with no network, and a forged or injected return fails as it would at Google.
