<?php

namespace Omniauth\OAuth\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use Psr\Clock\ClockInterface;

/**
 * The providers a host serves, by name. Marco's decision QA7: Google alone
 * today; another one is added by its configuration the day it has
 * credentials - no code (fromConfig()).
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
     *     google:   { client_id: …, client_secret: …, redirect_uri: …, scopes: [openid, email, profile], hosted_domain: ~ }
     *     facebook: { class: League\OAuth2\Client\Provider\Facebook, client_id: …, client_secret: …, redirect_uri: …,
     *                 options: { graphApiVersion: v19.0 }, scopes: [email, public_profile],
     *                 fields: { subject: id, email: email, verified: ~, name: name } }
     *     other:    { authorize_url: …, token_url: …, userinfo_url: …, client_id: …, … }   (league's GenericProvider)
     *
     * "google" (or any entry of "type: google") is GoogleProvider; an entry
     * with a "class" is that league provider; one with the three addresses is
     * league's GenericProvider. An entry with no client_id is left out: a
     * provider without credentials is not served.
     *
     * @param array<string, array<string, mixed>> $config
     * @param array<string, mixed>                $collaborators league's, for every provider (an "httpClient")
     */
    public static function fromConfig(array $config, ?ClockInterface $clock = null, array $collaborators = []): self
    {
        $providers = [];
        foreach ($config as $name => $entry) {
            $name = (string) $name;
            if ('' === (string) ($entry['client_id'] ?? '')) {
                continue;
            }
            $credentials = ['clientId' => (string) $entry['client_id'], 'clientSecret' => (string) ($entry['client_secret'] ?? ''), 'redirectUri' => (string) ($entry['redirect_uri'] ?? '')];
            if ('' === $credentials['redirectUri']) {
                throw new \InvalidArgumentException(\sprintf('The "%s" provider has no redirect_uri: its return address is fixed by its configuration.', $name));
            }
            $scopes = array_values(array_map('strval', (array) ($entry['scopes'] ?? [])));
            $fields = \is_array($entry['fields'] ?? null) ? $entry['fields'] : [];
            $type = $entry['type'] ?? ('google' === $name ? 'google' : null);
            if ('google' === $type) {
                $providers[] = new GoogleProvider($credentials['clientId'], $credentials['clientSecret'], $credentials['redirectUri'], $scopes ?: GoogleProvider::SCOPES, $entry['hosted_domain'] ?? null, $clock, $collaborators, $name);
                continue;
            }
            $options = $credentials + (\is_array($entry['options'] ?? null) ? $entry['options'] : []);
            if (isset($entry['class'])) {
                $class = (string) $entry['class'];
                if (!is_a($class, AbstractProvider::class, true)) {
                    throw new \InvalidArgumentException(\sprintf('The "%s" provider\'s class "%s" is not a league/oauth2-client provider.', $name, $class));
                }
                $league = new $class($options, $collaborators);
            } elseif (isset($entry['authorize_url'], $entry['token_url'], $entry['userinfo_url'])) {
                $league = new GenericProvider($options + [
                    'urlAuthorize' => (string) $entry['authorize_url'],
                    'urlAccessToken' => (string) $entry['token_url'],
                    'urlResourceOwnerDetails' => (string) $entry['userinfo_url'],
                    'scopeSeparator' => ' ',
                ] + (isset($fields['subject']) ? ['responseResourceOwnerId' => (string) $fields['subject']] : []), $collaborators);
            } else {
                throw new \InvalidArgumentException(\sprintf('The "%s" provider names neither a league provider\'s class nor its three addresses (authorize_url, token_url, userinfo_url).', $name));
            }
            $providers[] = new LeagueProvider($name, $league, $scopes, $fields);
        }

        return new self(...$providers);
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
