<?php

namespace Omniauth\OAuth\Tests;

use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Provider\Provider;
use Omniauth\OAuth\Provider\ProviderFactory;
use Omniauth\OAuth\Provider\Providers;
use Omniauth\OAuth\Testing\FakeProvider;
use PHPUnit\Framework\TestCase;

/** The providers served, by configuration: each provider package's factory makes its own kind. */
final class ProvidersTest extends TestCase
{
    public function testEachEntryIsMadeByTheFactoryOfItsKind(): void
    {
        $providers = Providers::configured([
            'google' => ['client_id' => 'g-id', 'redirect_uri' => '/login/google/callback'],
            'facebook' => ['client_id' => '', 'redirect_uri' => '/connect/facebook/check'],
            'staging' => ['type' => 'fake', 'client_id' => 's-id', 'redirect_uri' => 'https://staging.example/cb'],
        ], self::factory('nothing'), self::factory('google'), self::factory('fake'));

        self::assertSame(['google', 'staging'], $providers->names(), 'a provider without credentials is not served');
        self::assertCount(2, $providers);
        $google = $providers->get('google');
        self::assertInstanceOf(FakeProvider::class, $google);
        self::assertSame('/login/google/callback', $google->redirectUri);
    }

    public function testAProviderWithoutItsReturnAddressOrItsFactoryIsAMistake(): void
    {
        foreach ([
            [['google' => ['client_id' => 'g']], [self::factory('google')]],
            [['x' => ['client_id' => 'x', 'redirect_uri' => '/x']], [self::factory('google')]],
            [['google' => ['client_id' => 'g', 'redirect_uri' => '/x']], []],
        ] as [$config, $factories]) {
            try {
                Providers::configured($config, ...$factories);
                self::fail((string) json_encode($config));
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testTheFormerFromConfigNeedsGooglesPackage(): void
    {
        if (class_exists('Omniauth\Google\GoogleFactory')) {
            self::markTestSkipped('omniauth/google is installed beside: its own tests cover the deprecated path.');
        }
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('omniauth/google');
        @Providers::fromConfig(['google' => ['client_id' => 'g', 'redirect_uri' => '/x']]);
    }

    /** A return path, not an address: each trip's address is on its own origin, and the exchange compares it. */
    public function testAReturnPathTakesTheOriginOfEachTrip(): void
    {
        $fake = new FakeProvider('google', '/login/google/callback');
        $first = Authorization::fresh('https://lesringostars.localhost:8443');
        $second = Authorization::fresh('http://localhost:8132');
        parse_str((string) parse_url($fake->authorizationUrl($first), \PHP_URL_QUERY), $one);
        parse_str((string) parse_url($fake->authorizationUrl($second), \PHP_URL_QUERY), $two);
        self::assertSame(['https://lesringostars.localhost:8443/login/google/callback', 'http://localhost:8132/login/google/callback'], [$one['redirect_uri'], $two['redirect_uri']]);

        $code = $fake->consent($fake->authorizationUrl($first), ['sub' => '1'])['code'];
        self::assertSame('1', $fake->identify($code, Authorization::fromArray($first->toArray()) ?? $first)->subject, 'the attempt keeps the origin');

        // The same trip's values on another origin: not the address the code was given to.
        $code = $fake->consent($fake->authorizationUrl($first), ['sub' => '1'])['code'];
        $this->expectExceptionMessage('redirect_uri');
        $fake->identify($code, new Authorization($first->state, $first->verifier, $first->nonce, 'https://evil.example'));
    }

    public function testAReturnPathNeedsAnOrigin(): void
    {
        $this->expectException(\LogicException::class);
        (new FakeProvider('google', '/login/google/callback'))->authorizationUrl(Authorization::fresh());
    }

    /** A factory of $kind's: an entry named so, or of that type. */
    private static function factory(string $kind): ProviderFactory
    {
        return new class($kind) implements ProviderFactory {
            public function __construct(private readonly string $kind)
            {
            }

            public function create(string $name, array $entry): ?Provider
            {
                return $this->kind === ($entry['type'] ?? $name) ? new FakeProvider($name, \is_string($entry['redirect_uri'] ?? null) ? $entry['redirect_uri'] : '', \is_string($entry['client_id'] ?? null) ? $entry['client_id'] : '') : null;
            }
        };
    }
}
