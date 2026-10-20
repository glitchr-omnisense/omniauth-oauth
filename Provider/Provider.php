<?php

namespace Omniauth\OAuth\Provider;

use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Identity;

/**
 * An identity provider: where to send the visitor, then whom the code that
 * came back vouches for. Its return address is its own, fixed at its
 * configuration (never taken from a request).
 */
interface Provider
{
    /** Its key: the {provider} of the host's routes, Identities' $provider ("google"). */
    public function name(): string;

    /** The address to send the visitor to, carrying the state, the PKCE challenge and the nonce. */
    public function authorizationUrl(Authorization $authorization): string;

    /**
     * Exchanges the code (with the PKCE verifier) and reads whom it vouches for.
     *
     * @throws ProviderError
     */
    public function identify(string $code, Authorization $authorization): Identity;
}
