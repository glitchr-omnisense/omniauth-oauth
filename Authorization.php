<?php

namespace Omniauth\OAuth;

/**
 * What one trip to a provider is bound to, drawn at the beginning and kept in
 * the attempt (never in the answer): the state the return must bring back
 * (against a forged return: login CSRF), the PKCE verifier whose S256
 * challenge goes in the authorization address (against a code stolen or
 * injected: only the one who began can exchange it, RFC 7636), and the nonce
 * an ID token must carry (OpenID Connect, against a token replayed).
 */
final readonly class Authorization
{
    public function __construct(
        public string $state,
        /** 43 characters of base64url: RFC 7636 §4.1 asks 43 to 128. */
        public string $verifier,
        public string $nonce,
    ) {
    }

    /** Three new values, 32 random bytes each. */
    public static function fresh(): self
    {
        return new self(self::random(), self::random(), self::random());
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

    /** @return array{state: string, verifier: string, nonce: string} what the attempt keeps */
    public function toArray(): array
    {
        return ['state' => $this->state, 'verifier' => $this->verifier, 'nonce' => $this->nonce];
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

        return new self($kept['state'], $kept['verifier'], $kept['nonce']);
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
