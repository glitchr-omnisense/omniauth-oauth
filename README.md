# omniauth/oauth

Sign-in through identity providers for [omniscient/omniauth](https://github.com/glitchr-studio/omniauth),
**under any PHP host**, with no OAuth library - what every provider shares: the trip out (the
authorization address, its state, PKCE verifier and nonce kept in the attempt, the return address
on the host the trip began at), the trip back (the state compared, the code exchanged with the
verifier), and **who it is**: the account linked to
the provider's own identifier (`sub`), an account linked by its address only when the provider
says the address is verified, and never an account created behind the visitor's back. Each
provider is a package of its own: [omniauth/google](https://github.com/glitchr-studio/omniauth-google)
first (Marco's decision, 2026-10-21, the shape of omnishield's captchas).

```php
use Omniauth\{ArrayState, Context, Omniauth, Status};
use Omniauth\Method\Methods;
use Omniauth\OAuth\{NoSecondFactorLinking, OAuthMethod};
use Omniauth\Google\GoogleProvider;                       // omniauth/google
use Omniauth\OAuth\Provider\Providers;

$methods = new Methods([/* the password, the code by e-mail, TOTP... */]);
$methods->add(new OAuthMethod(
    $accounts,                                             // your accounts, behind Omniauth\Contract\Accounts
    $identities,                                           // provider + sub -> account, behind Omniauth\Contract\Identities
    new Providers(new GoogleProvider($clientId, $clientSecret, '/login/google/callback')),
    new NoSecondFactorLinking($methods),                   // QA3: an account with a second factor is not linked by its address
));
$omniauth = new Omniauth($accounts, $methods, new ArrayState($_SESSION));
$context = new Context(origin: 'https://example.org', host: 'example.org', ip: $_SERVER['REMOTE_ADDR']);

// /connect/google
header('Location: '.$omniauth->begin('oauth', $context, ['provider' => 'google'])->payload);

// /login/google/callback
$result = $omniauth->verify('oauth', $context, $_GET);    // code and state, as Google sends them back
match ($result->status) {
    Status::Authenticated => /* renew the session id, keep $result->account's handle */,
    Status::SecondFactorRequired => /* the account has one: it follows Google too (QA2) */,
    Status::IdentityUnknown => /* keep $result->identity in the session, show the sign-up */,
    Status::Failed => /* the sign-in page, $result->reason translated */,
};
```

It requires omniscient/omniauth alone: no OAuth library, no HTTP client (each provider package
brings its own - omniauth/google, league/oauth2-google: Marco's decision QA6, league there only).
No bundle, no kernel, no container.

## The shape

| | |
|---|---|
| `OAuthMethod` | a first factor (`Challenging`, `Enrolling`): `begin()`/`verify()` sign in, `enrolBegin()`/`enrolConfirm()` link a provider from the settings, `adopt()` links the account a sign-up just made |
| `Authorization` | the trip's three values - state, PKCE verifier (and its S256 challenge), nonce - and the origin it began at, kept in the attempt, never in the answer; `returnAddress()` puts a provider's return path on that origin |
| `Identity` | whom the provider vouched for: provider, subject, address, whether it is verified, name, the claims as they came |
| `Provider\Provider` | where to send the visitor, then whom the code vouches for; the return address (or path) is its configuration's |
| `Provider\ProviderFactory` | makes one kind of provider from a host's configuration: each provider package has its own (`Omniauth\Google\GoogleFactory`) |
| `Provider\Providers` | the providers served, by name; `configured()` makes them through the factories (`fromConfig()`, deprecated, through omniauth/google's) |
| `Contract\EmailLinking`, `NoSecondFactorLinking` | may an account be linked by its address alone? (QA3) |
| `Testing\FakeProvider` | an authorization server in memory that honours PKCE, codes once and the nonce: tests sign in with no network |

## Marco's decisions, where they live

- **QA2, a second factor after Google**: in omniauth's core rule (`EnrolledSecondFactors::AFTER`
  holds `Factor::OAuth`); this method is a first factor, so the conductor asks the second one of an
  account that has it. lesringostars today signs in by Google without it.
- **QA3, linking**: by `sub` first (`Identities::owner()`); by the address only when the provider
  says it is verified (Google's `email_verified`), never for an account the rule refuses
  (`NoSecondFactorLinking`; omnibase adds its administration roles) nor for one already linked to
  another subject - the person then links from the settings (`not-enrolled`,
  `link-from-settings`); otherwise `Status::IdentityUnknown`, which the host turns into its sign-up
  (the 500 "User identifier is NULL" of lesringostars' transient account cannot happen: no account
  is made here).
- **QA6, league/oauth2-client**: in omniauth/google only; neither this package, the core nor the
  bridges require it.
- **QA7, Google only**, and **one package per provider** (2026-10-21): omniauth/google; another
  provider is a package of its own the day a site asks for it.

## Documentation

- [Installation, in plain PHP](docs/installation.md)
- [The method and its linking rule](docs/oauth.md)
- [The providers](docs/providers.md)

## Verified, and not

- Verified (omniauth's harness, `docker compose run --rm omniauth test` in the core's `docker/`, PHP
  8.4; every file linted on PHP 8.2):
  - the trip, through the conductor, on the fake provider: the address carries the state, the S256
    challenge of the verifier kept and the nonce, never the verifier; a verified address links its
    account, then the subject alone signs in, whatever the address says later; an unverified (or
    unspoken) address finds no account; a user name that looks like the address is not the
    account's address; an unknown person is `IdentityUnknown` with what a sign-up fills in, no
    account made, and `adopt()` links the account made afterwards; an account with the code by
    e-mail passes it after Google (QA2); `NoSecondFactorLinking` and `byEmail: false` refuse to link
    by the address; an address does not move a link to another subject; a banned account is refused
    after the provider vouched for it; the attempt crosses requests as arrays;
  - **forged returns refused**: a forged or missing state (refused before any exchange - no request
    reaches the provider -, and the honest return after it finds nothing kept); a return this
    visitor never began (login CSRF: an attacker's own consented return in the victim's browser);
    **a code injected into another trip** (the victim's state, the attacker's code): the exchange
    with this trip's verifier is refused, as an authorization server honouring PKCE refuses it; a
    return replayed; a trip older than the attempt; `access_denied`; another provider's return;
  - from the settings: a provider linked whatever its address, a subject another account holds
    refused, one identity per provider and account, the state checked there too;
  - **a return path on the host of each trip** (a long-running worker serving two hosts: each
    visitor returns where they left from, the exchange is refused for another origin than the
    trip's);
  - the providers by configuration, through each kind's factory (an entry without credentials left
    out, one without a return address or a factory refused);
  - `docs/installation.md` run as written; in plain PHP (`BareTest`), the sign-ins by hand load
    nothing but omniauth, the PSR interfaces and the password hasher - no OAuth library, no class
    of a framework, of hwi/oauth-bundle, of the other omniauth packages or of an application.
  - Google itself: [omniauth/google](https://github.com/glitchr-studio/omniauth-google)'s own
    tests (its answers recorded).
- Not verified: **a real Google** - no client id and secret were at hand: the recorded answers are
  written from Google's documentation, not captured, and the ID token's signature is not Google's
  (the method does not check it: a token from the token endpoint over TLS, OpenID Connect Core
  §3.1.3.7 (6)); Google honouring PKCE and the nonce for this client (the fake server does, Google
  documents it); a host's store (`Base\Auth\UserIdentities` on the `userIdentity` table, steps AU4
  and AU5's core part) and the bridges' routes around the trip (AU6, AU8).

## Licence

MIT.
