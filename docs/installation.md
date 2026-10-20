---
title: Installation
order: 1
---

# Installation, in plain PHP

```sh
composer require omniscient/omniauth omniauth/oauth
```

It requires omniscient/omniauth, league/oauth2-client and league/oauth2-google (framework-free;
league talks HTTP through Guzzle). No bundle, no framework: the links between your accounts and
their providers stay in your table, behind omniauth's `Contract\Identities` (a provider, the
person's identifier there - `sub` -, the account).

The whole thing by hand - the in-memory stores of `Omniauth\Testing` stand in for yours, and
`Omniauth\OAuth\Testing\FakeProvider` for Google and the person consenting there:

```php
<?php

require 'vendor/autoload.php';

use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\Method\Methods;
use Omniauth\OAuth\NoSecondFactorLinking;
use Omniauth\OAuth\OAuthMethod;
use Omniauth\OAuth\Provider\Providers;
use Omniauth\OAuth\Testing\FakeProvider;
use Omniauth\Omniauth;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\TestAccount;

$store = new InMemoryStore($ringo = new TestAccount('42', 'ringo', 'ringo@example.org'));
// Yours: new GoogleProvider($clientId, $clientSecret, 'https://example.org/login/google/callback')
$google = new FakeProvider('google', redirectUri: 'https://example.org/login/google/callback');

$session = [];                                             // $_SESSION, in a real page
$methods = new Methods();
$methods->add(new OAuthMethod($store, $store, new Providers($google), new NoSecondFactorLinking($methods)));
$omniauth = new Omniauth(accounts: $store, methods: $methods, state: new ArrayState($session));
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: '203.0.113.7');

// /connect/google: the visitor is sent to the provider.
$challenge = $omniauth->begin('oauth', $context, ['provider' => 'google']);
// header('Location: '.$challenge->payload); the person consents; the browser comes back with ?code=…&state=…
$return = $google->consent($challenge->payload, ['sub' => '108204', 'email' => 'ringo@example.org', 'email_verified' => true]);

// /login/google/callback: the return's query, as it is.
$result = $omniauth->verify('oauth', $context, $return);
echo $result->status->value, ' as ', $result->account->identifier, ', linked to google ', $ringo->identities['google'], "\n";
// authenticated as ringo, linked to google 108204

// Someone no account knows: a result for the sign-up page, no account made.
$return = $google->consent($omniauth->begin('oauth', $context)->payload, ['sub' => '9001', 'email' => 'john@example.org', 'email_verified' => true]);
$result = $omniauth->verify('oauth', $context, $return);
echo $result->status->value, ': ', $result->identity->email, "\n";
// identity-unknown: john@example.org
```

What your pages do around it is the host's part: the start route redirects to
`$challenge->payload`; the return route hands its query to `verify()` and, on `Authenticated`,
renews its session id and keeps the account's handle; on `SecondFactorRequired` it shows the
second-factor page (an account that has one passes it after Google too: Marco's decision QA2); on
`IdentityUnknown` it keeps `$result->identity` **in its session** and shows its sign-up, then calls
`OAuthMethod::adopt($account, $identity)` once the account exists; on a failure, the sign-in page
with `$result->reason` translated.

Next: [the method and its linking rule](oauth.md), [the providers](providers.md).
