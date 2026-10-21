<?php

namespace Omniauth\OAuth\Provider;

use Psr\Clock\ClockInterface;

/**
 * The providers a host serves, by name. Marco's decisions: Google alone
 * today (QA7), and one package per provider (2026-10-21) - omniauth/google
 * first; configured() makes them through each package's factory.
 */
final class Providers implements \IteratorAggregate, \Countable
{
    /** @var array<string, Provider> */
    private array $providers = [];

    public function __construct(Provider ...$providers)
    {
        foreach ($providers as $provider) {
            $this->providers[$provider->name()] = $provider;
        }
    }

    /**
     * From a host's configuration (omniauth.yaml's "oauth" tree, config/omniauth.php's):
     *
     *     google: { client_id: …, client_secret: …, redirect_uri: /login/google/callback, scopes: [openid, email, profile] }
     *
     * Each entry is made by the first factory that knows its kind (omniauth/google's
     * GoogleFactory for "google": one package per provider). An entry with no
     * client_id is left out: a provider without credentials is not served. Its
     * redirect_uri is an absolute address, or a path the origin of each trip's
     * request completes (Authorization::returnAddress()): under a long-running
     * worker the visitor returns to the host they left from.
     *
     * @param array<string, array<string, mixed>> $config
     */
    public static function configured(array $config, ProviderFactory ...$factories): self
    {
        $providers = [];
        foreach ($config as $name => $entry) {
            $name = (string) $name;
            if ('' === (string) ($entry['client_id'] ?? '')) {
                continue;
            }
            if ('' === (string) ($entry['redirect_uri'] ?? '')) {
                throw new \InvalidArgumentException(\sprintf('The "%s" provider has no redirect_uri: its return address (or path) is its configuration\'s.', $name));
            }
            foreach ($factories as $factory) {
                $provider = $factory->create($name, $entry);
                if (null !== $provider) {
                    $providers[] = $provider;
                    continue 2;
                }
            }
            throw new \InvalidArgumentException(\sprintf('No provider factory makes "%s" (type "%s"): install its package (omniauth/%s) and pass its factory.', $name, (string) ($entry['type'] ?? $name), (string) ($entry['type'] ?? $name)));
        }

        return new self(...$providers);
    }

    /**
     * @deprecated use Providers::configured() with omniauth/google's
     *             GoogleFactory: Google moved to its own package (this one requires no OAuth
     *             library any more). Kept for one release; it serves Google entries alone.
     *
     * @param array<string, array<string, mixed>> $config
     * @param array<string, mixed>                $collaborators league's, for every provider (an "httpClient")
     */
    public static function fromConfig(array $config, ?ClockInterface $clock = null, array $collaborators = []): self
    {
        @trigger_error('Providers::fromConfig() is deprecated: use Providers::configured() with omniauth/google\'s GoogleFactory.', \E_USER_DEPRECATED);
        $factory = 'Omniauth\\Google\\GoogleFactory';
        if (!class_exists($factory)) {
            throw new \LogicException('Google moved to its own package: composer require omniauth/google, then Providers::configured($config, new GoogleFactory()).');
        }
        $made = new $factory($clock, $collaborators);
        if (!$made instanceof ProviderFactory) {
            throw new \LogicException(\sprintf('%s is no %s.', $factory, ProviderFactory::class));
        }

        return self::configured($config, $made);
    }

    public function has(string $name): bool
    {
        return isset($this->providers[$name]);
    }

    public function get(string $name): ?Provider
    {
        return $this->providers[$name] ?? null;
    }

    /** @return list<string> what the sign-in page offers */
    public function names(): array
    {
        return array_keys($this->providers);
    }

    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->providers);
    }

    public function count(): int
    {
        return \count($this->providers);
    }
}
