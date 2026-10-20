---
title: The method
order: 2
---

# The method

`OAuthMethod` is a first factor (`Factor::OAuth`), `Challenging` and `Enrolling`:

```php
new OAuthMethod(
    accounts: $accounts,          // Omniauth\Contract\Accounts
    identities: $identities,      // Omniauth\Contract\Identities: provider + sub -> account
    providers: new Providers(new GoogleProvider($id, $secret, $redirectUri)),
    byEmail: new NoSecondFactorLinking($methods),   // true (any account), false (never), or a rule
);
```

## The trip

| | |
|---|---|
| `begin()` (`['provider' => 'google']`, or nothing when one provider is served) | draws a state, a PKCE verifier and a nonce (32 random bytes each, base64url), keeps them in the attempt with the provider's name, answers `Challenge::redirect()` with the authorization address: the state, the S256 challenge, the nonce, the configured return address and scopes. The verifier never leaves the server. |
| `verify()` (the return's query: `code`, `state`, or `error`) | takes what the attempt kept - **once**: a return replayed finds nothing, `expired` -, compares the state in constant time **before anything else** (a return this visitor did not begin is not read further: no exchange, no request), then has the provider exchange the code **with the verifier** and read the person. |

The state stops a return the visitor did not begin (login CSRF: an attacker's own code landed in
the victim's browser). PKCE stops a code used in a trip it was not issued for (a code stolen from
a log or a referrer, or injected with the victim's state): the provider refuses to exchange it with
another trip's verifier. The nonce ties the ID token to the trip. What the attempt keeps lives as
long as the attempt (ten minutes).

## Who it is: the linking rule (QA3)

1. **The account linked to the provider's subject** (`Identities::owner($provider, $sub)`), whatever
   the address says now: Google's `sub` is the person's stable identifier there; an address can
   change hands.
2. Else, **only when the provider says the address is verified** (Google's `email_verified`), the
   account of that address (`Accounts::byIdentifier()`, then `Accounts::email()` compared, case
   aside: a user name that looks like the address is not it) - linked there and then
   (`Identities::link()`), unless:
   - `byEmail` refuses it: `false` never links by an address; `NoSecondFactorLinking` refuses an
     account that set up a second factor (Marco's QA3: never for an account with a second factor or
     an administration role - omnibase's own rule adds the roles, step AU4);
   - the account is linked to another subject of that provider already: an address does not move
     a link.
   Then: `not-enrolled`, reason `link-from-settings` - the person signs in otherwise and links the
   provider from the settings.
3. Else **nobody**: `Status::IdentityUnknown`, `$result->identity` (a `PendingIdentity`: provider,
   subject, address, whether it is verified, name). No account is created here - not even a
   transient one (lesringostars' hwi/oauth-bundle made one, and an address without an account
   ended in a 500 "User identifier is NULL"). The host shows its sign-up, prefilled; once the
   account exists, `adopt($account, $identity)` links it. Keep the identity in the session, never
   in a form field.

An address the provider does not vouch for is **never looked up**: an unverified address finds no
account, and the sign-up knows it is not proved (`emailVerified: false`).

## After it

The conductor does what it does after any first factor: `Accounts::check()` (banned, locked...),
then the second-factor rule - **an account that has a second factor passes it after Google**
(Marco's QA2: `EnrolledSecondFactors::AFTER` holds `Factor::OAuth`; lesringostars today signs in
by Google without it).

## From the settings

```php
$enrolment = $omniauth->enrol(Factor::OAuth, $account);
$challenge = $enrolment->begin($context, ['provider' => 'google']);   // redirect
$enrolled = $enrolment->confirm($context, $return);                   // the return's query
```

The same trip, state and PKCE included, in the enrolment's own attempt (a sign-in in progress is
not touched). The address does not matter there (the person is signed in); the subject is refused
when another account holds it (`linked-elsewhere`), and an account keeps one identity per provider
(`other-identity`). With one return address per provider, the host tells the two apart by whether
the visitor is signed in: signed in, `enrol()->confirm()`; not, `verify()`.

## Refusals

`bad-credentials` with a stable reason: `unknown-provider` (at the beginning), `state-mismatch`,
`provider-denied` (the person said no: `error=access_denied`), `provider-error`, `missing-code`,
`exchange-failed` (the provider refused the code: used, expired, or not this trip's verifier),
`invalid-id-token`, `no-subject`, `hosted-domain`, and from the settings `linked-elsewhere`,
`other-identity`; `not-enrolled` / `link-from-settings` (above); `expired` when the attempt kept
nothing. The provider's own message is for the server's log (`ProviderError::getMessage()`), not
the page.

Not here: turning a link off. `Contract\Identities` has no `unlink()` yet; it comes with omnibase's
store (AU4) and the `userIdentity` table.
