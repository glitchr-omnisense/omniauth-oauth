<?php

namespace Omniauth\OAuth\Tests\Fixtures;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Provider\GoogleProvider;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\RequestInterface;

/**
 * GoogleProvider over league/oauth2-google with Google's answers recorded
 * (recorded/): league and Guzzle do everything as they would, but the HTTP
 * handler hands the recorded responses out and keeps every request sent.
 *
 * The recordings are the shapes Google's OpenID Connect documentation gives
 * (the token endpoint's JSON, the ID token's claims, the userinfo's JSON, an
 * invalid_grant), written by hand - not captured: no Google credentials were
 * at hand. The ID token is assembled at test time from id-token.json, its
 * nonce the trip's; its signature is not Google's, and the method does not
 * check it (OpenID Connect Core §3.1.3.7 (6): a token from the token endpoint,
 * over TLS).
 */
final class Google
{
    public const CLIENT_ID = '1234987819200-omniauth.apps.googleusercontent.com';
    public const CLIENT_SECRET = 'GOCSPX-omniauth-recorded-secret';
    public const REDIRECT = 'https://example.org/login/google/callback';

    public readonly GoogleProvider $provider;
    public readonly MockHandler $answers;
    /** @var list<array{request: RequestInterface}> */
    public array $sent = [];

    public function __construct(?ClockInterface $clock = null, ?string $hostedDomain = null)
    {
        $this->answers = new MockHandler();
        $stack = HandlerStack::create($this->answers);
        $stack->push(Middleware::history($this->sent));
        $this->provider = new GoogleProvider(self::CLIENT_ID, self::CLIENT_SECRET, self::REDIRECT, hostedDomain: $hostedDomain, clock: $clock, collaborators: ['httpClient' => new Client(['handler' => $stack])]);
    }

    /** The token endpoint's answer, its ID token carrying $nonce and $claims over the recorded ones (null removes one); no ID token when $claims is false. */
    public function token(string $nonce, array|false $claims = []): self
    {
        $token = self::recorded('token');
        if (false === $claims) {
            unset($token['id_token']);
        } else {
            $token['id_token'] = self::idToken(array_filter($claims + ['nonce' => $nonce] + self::recorded('id-token'), static fn ($v) => null !== $v));
        }
        $this->answers->append(new Response(200, ['Content-Type' => 'application/json; charset=utf-8'], json_encode($token, \JSON_THROW_ON_ERROR)));

        return $this;
    }

    public function userinfo(array $claims = []): self
    {
        $this->answers->append(new Response(200, ['Content-Type' => 'application/json; charset=utf-8'], json_encode($claims + self::recorded('userinfo'), \JSON_THROW_ON_ERROR)));

        return $this;
    }

    public function invalidGrant(): self
    {
        $this->answers->append(new Response(400, ['Content-Type' => 'application/json; charset=utf-8'], json_encode(self::recorded('invalid-grant'), \JSON_THROW_ON_ERROR)));

        return $this;
    }

    /** @return array<string, string> the form the token request posted */
    public function posted(int $index = 0): array
    {
        parse_str((string) $this->sent[$index]['request']->getBody(), $form);

        return $form;
    }

    /** A JWT of Google's shape: RS256 header, the claims, a signature that is not Google's. */
    public static function idToken(array $claims): string
    {
        $part = static fn (array $json) => Authorization::base64url(json_encode($json, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));

        return $part(['alg' => 'RS256', 'kid' => 'c8ab71530972bba20b49f798a34d8a2b4b0b5e07', 'typ' => 'JWT']).'.'.$part($claims).'.'.Authorization::base64url(random_bytes(256));
    }

    /** @return array<string, mixed> */
    public static function recorded(string $name): array
    {
        return json_decode((string) file_get_contents(__DIR__."/recorded/$name.json"), true, 16, \JSON_THROW_ON_ERROR);
    }
}
