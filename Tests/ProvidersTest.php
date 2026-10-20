<?php

namespace Omniauth\OAuth\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\GenericProvider;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Provider\GoogleProvider;
use Omniauth\OAuth\Provider\LeagueProvider;
use Omniauth\OAuth\Provider\Providers;
use PHPUnit\Framework\TestCase;

/** QA7: Google today, another provider by its configuration alone. */
final class ProvidersTest extends TestCase
{
    public function testGoogleAndAnotherByConfiguration(): void
    {
        $sent = [];
        $answers = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], '{"access_token":"at-1","token_type":"bearer","expires_in":3600}'),
            new Response(200, ['Content-Type' => 'application/json'], '{"id":"42","email":"ringo@example.org","name":"Ringo"}'),
        ]);
        $stack = HandlerStack::create($answers);
        $stack->push(Middleware::history($sent));
        $providers = Providers::fromConfig([
            'google' => ['client_id' => 'g-id', 'client_secret' => 'g-secret', 'redirect_uri' => 'https://example.org/login/google/callback'],
            'facebook' => ['client_id' => '', 'client_secret' => '', 'redirect_uri' => 'https://example.org/connect/facebook-check'],
            'gitea' => [
                'client_id' => 'gt-id', 'client_secret' => 'gt-secret', 'redirect_uri' => 'https://example.org/connect/gitea-check',
                'authorize_url' => 'https://git.example/login/oauth/authorize', 'token_url' => 'https://git.example/login/oauth/access_token', 'userinfo_url' => 'https://git.example/api/v1/user',
                'scopes' => ['read:user'], 'fields' => ['subject' => 'id', 'email' => 'email', 'verified' => null, 'name' => 'name'],
            ],
        ], collaborators: ['httpClient' => new Client(['handler' => $stack])]);

        self::assertSame(['google', 'gitea'], $providers->names(), 'a provider without credentials is not served');
        self::assertInstanceOf(GoogleProvider::class, $providers->get('google'));
        $gitea = $providers->get('gitea');
        self::assertInstanceOf(LeagueProvider::class, $gitea);
        self::assertInstanceOf(GenericProvider::class, $gitea->league());

        $authorization = Authorization::fresh();
        parse_str((string) parse_url($gitea->authorizationUrl($authorization), \PHP_URL_QUERY), $query);
        self::assertSame(['read:user', $authorization->state, $authorization->challenge(), 'S256', 'https://example.org/connect/gitea-check'], [$query['scope'], $query['state'], $query['code_challenge'], $query['code_challenge_method'], $query['redirect_uri']]);

        $identity = $gitea->identify('code', $authorization);
        parse_str((string) $sent[0]['request']->getBody(), $form);
        self::assertSame($authorization->verifier, $form['code_verifier']);
        self::assertSame(['gitea', '42', 'ringo@example.org', 'Ringo'], [$identity->provider, $identity->subject, $identity->email, $identity->name]);
        self::assertFalse($identity->emailVerified, 'a provider that says nothing of the address does not vouch for it: no linking by it');
    }

    public function testAProviderWithoutItsReturnAddressOrItsShapeIsAMistake(): void
    {
        foreach ([
            ['google' => ['client_id' => 'g']],
            ['x' => ['client_id' => 'x', 'redirect_uri' => 'https://example.org/x']],
            ['x' => ['client_id' => 'x', 'redirect_uri' => 'https://example.org/x', 'class' => \stdClass::class]],
        ] as $config) {
            try {
                Providers::fromConfig($config);
                self::fail(json_encode($config));
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testALeagueProviderThatDrawsItsOwnVerifierIsRefused(): void
    {
        $league = new GenericProvider(['clientId' => 'x', 'redirectUri' => 'https://example.org/x', 'urlAuthorize' => 'https://p.example/a', 'urlAccessToken' => 'https://p.example/t', 'urlResourceOwnerDetails' => 'https://p.example/u', 'pkceMethod' => GenericProvider::PKCE_METHOD_S256]);

        $this->expectException(\LogicException::class);
        (new LeagueProvider('x', $league))->authorizationUrl(Authorization::fresh());
    }
}
