<?php

namespace Omniauth\OAuth\Testing;

use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Identity;
use Omniauth\OAuth\Provider\Provider;

/**
 * An authorization server in memory, for a host's tests and a first try: it
 * answers the authorization address as a provider does once the person
 * consented (consent(): the return's code and state), and exchanges a code
 * as a provider does - once, for the client and the return address it was
 * given to, and only with the PKCE verifier whose S256 challenge the
 * authorization carried (RFC 7636 §4.6); the nonce is the one the address
 * carried. So a test signs in with no network, and a forged or injected
 * return fails here as it would at Google.
 */
final class FakeProvider implements Provider
{
    public const AUTHORIZE = 'https://provider.test/authorize';

    /** @var array<string, array{challenge: string, nonce: string, client: string, redirect: string, person: Identity}> */
    private array $codes = [];
    /** @var list<array{code: string, verifier: string}> every exchange asked, in order */
    public array $exchanges = [];

    /** @param list<string> $scopes */
    public function __construct(
        private readonly string $name = 'google',
        public readonly string $redirectUri = 'https://example.org/login/google/callback',
        public readonly string $clientId = 'omniauth-test-client',
        private readonly array $scopes = ['openid', 'email', 'profile'],
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function authorizationUrl(Authorization $authorization): string
    {
        return self::AUTHORIZE.'?'.http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes),
            'state' => $authorization->state,
            'code_challenge' => $authorization->challenge(),
            'code_challenge_method' => 'S256',
            'nonce' => $authorization->nonce,
        ], '', '&', \PHP_QUERY_RFC3986);
    }

    /**
     * The person consents at the authorization address: what the browser
     * brings back to the return address (['code' => …, 'state' => …]).
     *
     * @param Identity|array{sub: string, email?: string, email_verified?: bool|string, name?: string} $person
     *
     * @return array{code: string, state: string}
     */
    public function consent(string $authorizationUrl, Identity|array $person): array
    {
        $query = self::query($authorizationUrl);
        if (($query['client_id'] ?? null) !== $this->clientId || ($query['redirect_uri'] ?? null) !== $this->redirectUri) {
            throw new \InvalidArgumentException('Not an authorization address of this client and return address.');
        }
        if ('S256' !== ($query['code_challenge_method'] ?? null) || '' === (string) ($query['code_challenge'] ?? '')) {
            throw new \InvalidArgumentException('An authorization address without its S256 challenge.');
        }
        if (\is_array($person)) {
            $email = isset($person['email']) ? (string) $person['email'] : null;
            $person = new Identity($this->name, (string) $person['sub'], $email, null !== $email && Identity::verified($person['email_verified'] ?? false), isset($person['name']) ? (string) $person['name'] : null, $person);
        }
        $code = bin2hex(random_bytes(16));
        $this->codes[$code] = ['challenge' => (string) $query['code_challenge'], 'nonce' => (string) ($query['nonce'] ?? ''), 'client' => $this->clientId, 'redirect' => $this->redirectUri, 'person' => $person];

        return ['code' => $code, 'state' => (string) ($query['state'] ?? '')];
    }

    /** @return array{error: string, state: string} the person said no */
    public function deny(string $authorizationUrl): array
    {
        return ['error' => 'access_denied', 'state' => (string) (self::query($authorizationUrl)['state'] ?? '')];
    }

    /** The return address the browser lands on with $return's parameters. */
    public function returnUrl(array $return): string
    {
        return $this->redirectUri.'?'.http_build_query($return, '', '&', \PHP_QUERY_RFC3986);
    }

    public function identify(string $code, Authorization $authorization): Identity
    {
        $this->exchanges[] = ['code' => $code, 'verifier' => $authorization->verifier];
        $grant = $this->codes[$code] ?? throw new ProviderError(ProviderError::EXCHANGE, 'invalid_grant: unknown or used code');
        unset($this->codes[$code]);   // a code serves once
        if (!hash_equals($grant['challenge'], $authorization->challenge())) {
            throw new ProviderError(ProviderError::EXCHANGE, 'invalid_grant: the code verifier does not match the challenge');
        }
        if ('' !== $grant['nonce'] && !hash_equals($grant['nonce'], $authorization->nonce)) {
            throw new ProviderError(ProviderError::ID_TOKEN, 'The ID token\'s nonce is not right.');
        }

        return $grant['person'];
    }

    /** @return array<string, string> */
    private static function query(string $url): array
    {
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);

        return array_map('strval', array_filter($query, 'is_scalar'));
    }
}
