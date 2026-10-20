<?php

namespace Omniauth\OAuth\Tests;

use Omniauth\Factor;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Tests\Fixtures\Google;
use Omniauth\OAuth\Tests\Fixtures\Kit;
use Omniauth\Testing\FixedClock;
use PHPUnit\Framework\TestCase;

/** Google over league/oauth2-google, its answers recorded: the address, the exchange, the ID token's checks. */
final class GoogleProviderTest extends TestCase
{
    private FixedClock $clock;

    protected function setUp(): void
    {
        $this->clock = new FixedClock('2026-10-21 12:00:00 UTC');
    }

    public function testTheAuthorizationAddress(): void
    {
        $google = new Google($this->clock);
        $authorization = Authorization::fresh();
        $url = $google->provider->authorizationUrl($authorization);
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);

        self::assertStringStartsWith('https://accounts.google.com/o/oauth2/v2/auth?', $url);
        self::assertSame([
            'client_id' => Google::CLIENT_ID,
            'code_challenge' => $authorization->challenge(),
            'code_challenge_method' => 'S256',
            'nonce' => $authorization->nonce,
            'redirect_uri' => Google::REDIRECT,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $authorization->state,
        ], self::sorted($query));
        self::assertStringNotContainsString($authorization->verifier, $url);
        self::assertSame([], $google->sent, 'no request');
    }

    public function testAHostedDomainGoesInTheAddress(): void
    {
        parse_str((string) parse_url((new Google($this->clock, 'beatles.example'))->provider->authorizationUrl(Authorization::fresh()), \PHP_URL_QUERY), $query);

        self::assertSame('beatles.example', $query['hd']);
    }

    public function testTheCodeIsExchangedWithTheVerifierAndThePersonReadFromTheIdToken(): void
    {
        $google = (new Google($this->clock))->token($nonce = 'n-'.bin2hex(random_bytes(8)));
        $authorization = new Authorization('the-state', 'v'.str_repeat('x', 42), $nonce);
        $identity = $google->provider->identify('4/0AQSTgQ-recorded-code', $authorization);

        self::assertCount(1, $google->sent, 'the token endpoint alone: the ID token says who');
        $request = $google->sent[0]['request'];
        self::assertSame(['POST', 'https://oauth2.googleapis.com/token'], [$request->getMethod(), (string) $request->getUri()]);
        self::assertSame([
            'client_id' => Google::CLIENT_ID,
            'client_secret' => Google::CLIENT_SECRET,
            'code' => '4/0AQSTgQ-recorded-code',
            'code_verifier' => $authorization->verifier,
            'grant_type' => 'authorization_code',
            'redirect_uri' => Google::REDIRECT,
        ], self::sorted($google->posted()));

        self::assertSame(['google', '110169484474386276334', 'ringo@example.org', true, 'Ringo Starr'], [$identity->provider, $identity->subject, $identity->email, $identity->emailVerified, $identity->name]);
        self::assertSame('Starr', $identity->claims['family_name']);
    }

    public function testTheIdTokensChecks(): void
    {
        $cases = [
            'another issuer' => [['iss' => 'https://evil.example'], ProviderError::ID_TOKEN],
            'the issuer without https' => [['iss' => 'accounts.google.com'], null],
            'another client' => [['aud' => 'someone-else.apps.googleusercontent.com'], ProviderError::ID_TOKEN],
            'several audiences, this client the authorized party' => [['aud' => [Google::CLIENT_ID, 'other'], 'azp' => Google::CLIENT_ID], null],
            'several audiences, another authorized party' => [['aud' => [Google::CLIENT_ID, 'other'], 'azp' => 'other'], ProviderError::ID_TOKEN],
            'past its time' => [['exp' => 1792584000 - 61], ProviderError::ID_TOKEN],
            'within the leeway' => [['exp' => 1792584000 - 30], null],
            'no lifetime' => [['exp' => null], ProviderError::ID_TOKEN],
            'issued in the future' => [['iat' => 1792584000 + 3600, 'exp' => 1792584000 + 7200], ProviderError::ID_TOKEN],
            'another nonce' => [['nonce' => 'replayed'], ProviderError::ID_TOKEN],
            'no subject' => [['sub' => null], ProviderError::SUBJECT],
        ];
        foreach ($cases as $case => [$claims, $reason]) {
            $google = new Google($this->clock);
            $authorization = Authorization::fresh();
            $google->token($authorization->nonce, $claims);
            try {
                $identity = $google->provider->identify('code', $authorization);
                self::assertNull($reason, $case.': refused');
                self::assertSame('110169484474386276334', $identity->subject, $case);
            } catch (ProviderError $e) {
                self::assertSame($reason, $e->reason, $case.': '.$e->getMessage());
            }
        }
    }

    public function testNotAJwt(): void
    {
        $google = new Google($this->clock);
        $google->answers->append(new \GuzzleHttp\Psr7\Response(200, ['Content-Type' => 'application/json'], json_encode(['id_token' => 'not.a-jwt'] + Google::recorded('token'))));

        self::assertSame(ProviderError::ID_TOKEN, self::refusal(fn () => $google->provider->identify('code', Authorization::fresh())));
    }

    public function testEmailVerifiedAsGoogleSendsIt(): void
    {
        foreach ([[true, true], ['true', true], [false, false], ['false', false], [null, false]] as [$claim, $verified]) {
            $google = new Google($this->clock);
            $authorization = Authorization::fresh();
            $google->token($authorization->nonce, ['email_verified' => $claim]);

            self::assertSame($verified, $google->provider->identify('code', $authorization)->emailVerified, var_export($claim, true));
        }
    }

    public function testAHostedDomainIsChecked(): void
    {
        foreach ([['beatles.example', null], ['apple.example', ProviderError::HOSTED_DOMAIN], [null, ProviderError::HOSTED_DOMAIN]] as [$hd, $reason]) {
            $google = new Google($this->clock, 'beatles.example');
            $authorization = Authorization::fresh();
            $google->token($authorization->nonce, ['hd' => $hd]);
            try {
                $google->provider->identify('code', $authorization);
                self::assertNull($reason);
            } catch (ProviderError $e) {
                self::assertSame($reason, $e->reason);
            }
        }
    }

    public function testWithoutAnIdTokenTheUserinfoIsReadThroughTheAccessToken(): void
    {
        $google = (new Google($this->clock))->token('unused', false)->userinfo();
        $identity = $google->provider->identify('code', Authorization::fresh());

        self::assertCount(2, $google->sent);
        $request = $google->sent[1]['request'];
        self::assertSame(['GET', 'https://openidconnect.googleapis.com/v1/userinfo'], [$request->getMethod(), (string) $request->getUri()]);
        self::assertSame('Bearer '.Google::recorded('token')['access_token'], $request->getHeaderLine('Authorization'));
        self::assertSame(['110169484474386276334', 'ringo@example.org', true], [$identity->subject, $identity->email, $identity->emailVerified]);
    }

    public function testAnIdTokenWithoutTheAddressIsCompletedByTheUserinfoOfTheSameSubject(): void
    {
        $google = new Google($this->clock);
        $authorization = Authorization::fresh();
        $google->token($authorization->nonce, ['email' => null, 'email_verified' => null])->userinfo();
        self::assertSame('ringo@example.org', $google->provider->identify('code', $authorization)->email);

        $google = new Google($this->clock);
        $google->token($authorization->nonce, ['email' => null, 'email_verified' => null])->userinfo(['sub' => 'someone-else']);
        self::assertSame(ProviderError::ID_TOKEN, self::refusal(fn () => $google->provider->identify('code', $authorization)));
    }

    public function testACodeGoogleRefuses(): void
    {
        $google = (new Google($this->clock))->invalidGrant();
        try {
            $google->provider->identify('used-code', Authorization::fresh());
            self::fail('refused');
        } catch (ProviderError $e) {
            self::assertSame(ProviderError::EXCHANGE, $e->reason);
            self::assertStringContainsString('invalid_grant', $e->getMessage());
        }
    }

    public function testThroughTheConductor(): void
    {
        $google = new Google($this->clock);
        $kit = new Kit(google: $google->provider);
        $url = $kit->depart();
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        $google->token($query['nonce']);
        $result = $kit->omniauth->verify('oauth', Kit::context(), ['code' => '4/0AQSTgQ-recorded-code', 'state' => $query['state'], 'scope' => 'email profile openid', 'authuser' => '0', 'prompt' => 'consent']);

        self::assertTrue($result->isAuthenticated());
        self::assertSame($kit->ringo, $result->account);
        self::assertSame([Factor::OAuth], $result->passed);
        self::assertSame(['google' => '110169484474386276334'], $kit->ringo->identities);
        self::assertSame(hash('sha256', $google->posted()['code_verifier'], true), self::unbase64url($query['code_challenge']), 'the verifier posted is the one whose challenge went out');
    }

    public function testAForgedReturnThroughTheConductorReachesNoEndpoint(): void
    {
        $google = new Google($this->clock);
        $kit = new Kit(google: $google->provider);
        $kit->depart();
        $result = $kit->omniauth->verify('oauth', Kit::context(), ['code' => 'stolen', 'state' => 'guessed']);

        self::assertSame('state-mismatch', $result->reason);
        self::assertSame([], $google->sent);
    }

    /** The reason of the ProviderError $call throws. */
    private static function refusal(\Closure $call): string
    {
        try {
            $call();
        } catch (ProviderError $e) {
            return $e->reason;
        }
        self::fail('No ProviderError.');
    }

    /** @return array<string, mixed> */
    private static function sorted(array $values): array
    {
        ksort($values);

        return $values;
    }

    private static function unbase64url(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/'));
    }
}
