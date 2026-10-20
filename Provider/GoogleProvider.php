<?php

namespace Omniauth\OAuth\Provider;

use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Identity;
use Omniauth\SystemClock;
use Psr\Clock\ClockInterface;

/**
 * Google, over league/oauth2-google, as an OpenID Connect provider: scopes
 * "openid email profile", a nonce in the authorization address, and the
 * person read from the ID token the exchange returns - its issuer
 * (accounts.google.com), its audience (this client; azp when there are
 * several), its lifetime, its nonce and, when a hosted domain is set, its
 * "hd" checked. The token comes straight from Google's token endpoint over
 * TLS: OpenID Connect Core §3.1.3.7 (6) lets the TLS server validation stand
 * in for its signature then, so no key set is fetched. With no ID token (or
 * one without the address), the userinfo endpoint is read through the access
 * token, and its subject must be the token's.
 *
 * "email_verified" is what says whether an account may be linked by its
 * address (QA3): a JSON boolean, or the string "true" Google once sent.
 */
final class GoogleProvider extends LeagueProvider
{
    public const SCOPES = ['openid', 'email', 'profile'];
    public const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
    /** Seconds of clock difference tolerated on exp and iat. */
    public const LEEWAY = 60;

    private readonly ClockInterface $clock;

    /**
     * @param string       $redirectUri  the return address, fixed (lesringostars: https://…/login/google/callback)
     * @param list<string> $scopes
     * @param string|null  $hostedDomain a Google Workspace domain the account must belong to ("hd"), or "*" for any
     * @param array<string, mixed> $collaborators league's: an "httpClient" (Guzzle) for tests and proxies
     */
    public function __construct(
        private readonly string $clientId,
        string $clientSecret,
        string $redirectUri,
        array $scopes = self::SCOPES,
        private readonly ?string $hostedDomain = null,
        ?ClockInterface $clock = null,
        array $collaborators = [],
        string $name = 'google',
    ) {
        $this->clock = $clock ?? new SystemClock();
        parent::__construct(
            $name,
            new Google(array_filter(['clientId' => $clientId, 'clientSecret' => $clientSecret, 'redirectUri' => $redirectUri, 'hostedDomain' => $hostedDomain], static fn ($v) => null !== $v), $collaborators),
            array_values(array_unique([...self::SCOPES, ...$scopes])),
            ['subject' => 'sub', 'email' => 'email', 'verified' => 'email_verified', 'name' => 'name'],
        );
    }

    protected function authorizationOptions(Authorization $authorization): array
    {
        return parent::authorizationOptions($authorization) + ['nonce' => $authorization->nonce];
    }

    protected function identity(AccessTokenInterface $token, Authorization $authorization): Identity
    {
        $idToken = $token->getValues()['id_token'] ?? null;
        $claims = \is_string($idToken) ? $this->claims($idToken, $authorization) : null;
        if (null !== $claims && \is_string($claims['email'] ?? null)) {
            return $this->fromClaims($claims['sub'] ?? null, $claims);
        }
        // No ID token, or one without the address: Google's userinfo, through the access token.
        $details = $this->details($token);
        if (null !== $claims && (string) ($details['sub'] ?? '') !== (string) ($claims['sub'] ?? '')) {
            throw new ProviderError(ProviderError::ID_TOKEN, 'The userinfo is not the ID token\'s subject.');
        }

        return $this->fromClaims($details['sub'] ?? null, ($claims ?? []) + $details);
    }

    /**
     * The ID token's claims, checked.
     *
     * @return array<string, mixed>
     *
     * @throws ProviderError
     */
    private function claims(string $idToken, Authorization $authorization): array
    {
        $parts = explode('.', $idToken);
        $payload = 3 === \count($parts) ? base64_decode(strtr($parts[1], '-_', '+/'), true) : false;
        $claims = false !== $payload ? json_decode($payload, true) : null;
        if (!\is_array($claims)) {
            throw new ProviderError(ProviderError::ID_TOKEN, 'The ID token is not a JWT.');
        }
        $now = $this->clock->now()->getTimestamp();
        $audience = $claims['aud'] ?? null;
        $failed = match (true) {
            !\in_array($claims['iss'] ?? null, self::ISSUERS, true) => 'issuer',
            !(\is_string($audience) ? $audience === $this->clientId : \is_array($audience) && \in_array($this->clientId, $audience, true)) => 'audience',
            \is_array($audience) && \count($audience) > 1 && ($claims['azp'] ?? null) !== $this->clientId => 'authorized party',
            !\is_int($claims['exp'] ?? null) || $claims['exp'] + self::LEEWAY <= $now => 'lifetime',
            \is_int($claims['iat'] ?? null) && $claims['iat'] - self::LEEWAY > $now => 'issued in the future',
            !\is_string($claims['nonce'] ?? null) || !hash_equals($authorization->nonce, $claims['nonce']) => 'nonce',
            null !== $this->hostedDomain && '*' !== $this->hostedDomain && ($claims['hd'] ?? null) !== $this->hostedDomain => 'hosted domain',
            null !== $this->hostedDomain && '*' === $this->hostedDomain && !\is_string($claims['hd'] ?? null) => 'hosted domain',
            default => null,
        };
        if (null !== $failed) {
            throw new ProviderError(str_starts_with($failed, 'hosted') ? ProviderError::HOSTED_DOMAIN : ProviderError::ID_TOKEN, \sprintf('The ID token\'s %s is not right.', $failed));
        }

        return $claims;
    }
}
