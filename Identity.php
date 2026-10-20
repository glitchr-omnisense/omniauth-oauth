<?php

namespace Omniauth\OAuth;

use Omniauth\PendingIdentity;

/**
 * Whom a provider vouched for, read from its ID token or its userinfo -
 * never from the return address's parameters.
 */
final readonly class Identity
{
    /** @param array<string, mixed> $claims what the provider said, as it said it */
    public function __construct(
        public string $provider,
        /** The person's stable identifier at the provider ("sub"): what links an account. */
        public string $subject,
        public ?string $email = null,
        /** Whether the provider says the address is the person's (Google's email_verified); false when it says nothing. */
        public bool $emailVerified = false,
        public ?string $name = null,
        public array $claims = [],
    ) {
        if ('' === $subject) {
            throw new \InvalidArgumentException('An identity has its subject.');
        }
    }

    /** What the conductor's IdentityUnknown result carries to the host's sign-up. */
    public function pending(): PendingIdentity
    {
        return new PendingIdentity($this->provider, $this->subject, $this->email, $this->emailVerified, $this->name);
    }

    /** A provider's "true": a JSON boolean, or the string some of them send. */
    public static function verified(mixed $claim): bool
    {
        return true === $claim || 'true' === $claim || 1 === $claim || '1' === $claim;
    }
}
