<?php

namespace Omniauth\OAuth\Provider;

/**
 * Makes the providers of one kind from a host's configuration: each provider
 * package has its own (omniauth/google's GoogleFactory), so this package
 * needs no OAuth library. Providers::configured() asks each factory in turn.
 */
interface ProviderFactory
{
    /**
     * The provider of this entry, or null when the entry is not of this
     * factory's kind.
     *
     * @param array<string, mixed> $entry the entry as configured: client_id, client_secret,
     *                                    redirect_uri (an absolute address, or a path the trip's
     *                                    origin completes), scopes, type, and the kind's own keys
     */
    public function create(string $name, array $entry): ?Provider;
}
