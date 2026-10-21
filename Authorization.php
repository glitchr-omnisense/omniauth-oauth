<?php

namespace Omniauth\OAuth;

/**
 * What one trip to a provider is bound to, drawn at the beginning and kept in
 * the attempt (never in the answer): the state the return must bring back
 * (against a forged return: login CSRF), the PKCE verifier whose S256
 * challenge goes in the authorization address (against a code stolen or
 * injected: only the one who began can exchange it, RFC 7636), and the nonce
 * an ID token must carry (OpenID Connect, against a token replayed) - and
 * the origin of the request that began the trip, against which a provider
 * configured with a return path ("/login/google/callback") makes its return
 * address: the host the visitor is on at that request, not the first one a
 * long-running worker served, and the same address again at the exchange
 * (RFC 6749 §4.1.3: the token request repeats the authorization's).
 */
final readonly class Authorization
{
    public function __construct(
        public string $state,
        /** 43 characters of base64url: RFC 7636 §4.1 asks 43 to 128. */
        public string $verifier,
        public string $nonce,
        /** The request's scheme and host at the beginning ("https://example.org:8443"), null when it is not known. */
        public ?string $origin = null,
    ) {
    }

    /** Three new values, 32 random bytes each; the beginning request's origin when the host knows it. */
    public static function fresh(?string $origin = null): self
    {
        return new self(self::random(), self::random(), self::random(), '' === $origin ? null : $origin);
    }

    /**
     * A provider's return address for this trip: an absolute address as it
     * is; a path ("/login/google/callback") on the trip's origin.
     */
    public function returnAddress(string $configured): string
    {
        if (!str_starts_with($configured, '/') || str_starts_with($configured, '//')) {
            return $configured;
        }
        if (null === $this->origin) {
            throw new \LogicException(\sprintf('The return path "%s" needs the origin of the request that began the trip (Context::$origin).', $configured));
        }

        return rtrim($this->origin, '/').$configured;
    }

    /** The verifier's S256 challenge: BASE64URL(SHA-256(verifier)), RFC 7636 §4.2. */
    public function challenge(): string
    {
        return self::base64url(hash('sha256', $this->verifier, true));
    }

    /** Whether a return brings back this state: compared in constant time. */
    public function matches(string $state): bool
    {
        return '' !== $state && hash_equals($this->state, $state);
    }

    /** @return array{state: string, verifier: string, nonce: string, origin?: string} what the attempt keeps */
    public function toArray(): array
    {
        return ['state' => $this->state, 'verifier' => $this->verifier, 'nonce' => $this->nonce] + (null !== $this->origin ? ['origin' => $this->origin] : []);
    }

    /** What the attempt gave back; null when anything is missing. */
    public static function fromArray(mixed $kept): ?self
    {
        if (!\is_array($kept)) {
            return null;
        }
        foreach (['state', 'verifier', 'nonce'] as $key) {
            if (!\is_string($kept[$key] ?? null) || '' === $kept[$key]) {
                return null;
            }
        }

        $origin = $kept['origin'] ?? null;

        return new self($kept['state'], $kept['verifier'], $kept['nonce'], \is_string($origin) && '' !== $origin ? $origin : null);
    }

    public static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function random(): string
    {
        return self::base64url(random_bytes(32));
    }
}
