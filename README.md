# omniauth/oauth - abandoned

**This package is abandoned.** Since 2026-10-23 the sign-in through identity providers (OAuth 2,
OpenID Connect) is part of [omniscient/omniauth](https://github.com/glitchr-studio/omniauth) itself,
under the same namespace and the same class names (`Omniauth\OAuth\OAuthMethod`,
`Omniauth\OAuth\Provider\Providers`, `Omniauth\OAuth\Testing\FakeProvider`...): the mechanics every
provider shares need no library, so they live in the core, and each provider is a package of its
own - [omniauth/google](https://github.com/glitchr-studio/omniauth-google) first -, as omnishield
has one package per captcha.

This last release holds no code: it requires omniscient/omniauth, which brings the classes. Replace
it in your `composer.json`:

```sh
composer remove omniauth/oauth
composer require omniscient/omniauth omniauth/google
```

Nothing else changes in your code. The documentation moved to omniauth's
[identity providers page](https://github.com/glitchr-studio/omniauth/blob/1.x/docs/oauth.md).

## Licence

MIT.
