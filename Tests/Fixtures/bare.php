<?php

/*
 * omniauth/oauth in plain PHP: no bundle, no container, no framework. The
 * conductor built by hand on the in-memory stores, a fake Google first: a
 * verified address links its account, then the subject alone signs in; an
 * unknown person is a result, not an account; a forged state; a code
 * injected into another trip; the code by e-mail after Google. Then Google
 * itself over league/oauth2-google, its answers recorded (a Guzzle handler):
 * the same sign-in. Prints what happened and every class and file PHP
 * loaded, as JSON. Argument: the autoloader.
 */

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Omniauth\ArrayState;
use Omniauth\Context;
use Omniauth\EmailCode\EmailCodeMethod;
use Omniauth\Method\Methods;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\NoSecondFactorLinking;
use Omniauth\OAuth\OAuthMethod;
use Omniauth\OAuth\Provider\GoogleProvider;
use Omniauth\OAuth\Provider\Providers;
use Omniauth\OAuth\Testing\FakeProvider;
use Omniauth\Omniauth;
use Omniauth\Result;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\RecordingSender;
use Omniauth\Testing\TestAccount;

require $autoload = $argv[1];

$clock = new FixedClock('2026-10-21 12:00:00 UTC');
$store = new InMemoryStore(
    $ringo = new TestAccount('1', 'ringo', 'ringo@example.org'),
    $paul = new TestAccount('2', 'paul', 'paul@example.org', emailCodeEnabled: true),
);
$sender = new RecordingSender();
$build = static function (FakeProvider|GoogleProvider $google) use ($store, $sender, $clock, &$session): Omniauth {
    $session = [];
    $methods = new Methods([new EmailCodeMethod($store, $store->emailCodes(), $sender, 'a-kernel-secret-of-thirty-two-bytes-or-more', clock: $clock)]);
    $methods->add(new OAuthMethod($store, $store, new Providers($google), new NoSecondFactorLinking($methods)));

    return new Omniauth($store, $methods, new ArrayState($session), clock: $clock);
};
$context = new Context('https://example.org', 'example.org', '203.0.113.7');
$seen = static fn (Result $r) => ['status' => $r->status->value, 'account' => $r->account?->identifier, 'passed' => array_map(fn ($f) => $f->value, $r->passed), 'offered' => array_map(fn ($f) => $f->value, $r->offered), 'failure' => $r->failure?->value, 'reason' => $r->reason];
$fake = new FakeProvider('google');
$omniauth = $build($fake);
$trip = static fn (array $person) => $fake->consent($omniauth->begin('oauth', $context)->payload, $person);

$report['linked'] = $seen($omniauth->verify('oauth', $context, $trip(['sub' => '108204', 'email' => 'ringo@example.org', 'email_verified' => true])));
$report['identities'] = $ringo->identities;
$report['by-subject'] = $seen($omniauth->verify('oauth', $context, $trip(['sub' => '108204', 'email' => 'starr@example.net'])));
$unknown = $omniauth->verify('oauth', $context, $trip(['sub' => '9001', 'email' => 'john@example.org', 'email_verified' => true]));
$report['unknown'] = $seen($unknown) + ['identity' => [$unknown->identity?->subject, $unknown->identity?->email, $unknown->identity?->emailVerified]];
$report['unverified'] = $seen($omniauth->verify('oauth', $context, $trip(['sub' => '9002', 'email' => 'ringo@example.org', 'email_verified' => false])));
$report['forged'] = $seen($omniauth->verify('oauth', $context, ['state' => 'forged'] + $trip(['sub' => '108204'])));
$theirs = $fake->consent($fake->authorizationUrl(Authorization::fresh()), ['sub' => '108204']);
parse_str((string) parse_url($omniauth->begin('oauth', $context)->payload, PHP_URL_QUERY), $mine);
$report['injected'] = $seen($omniauth->verify('oauth', $context, ['code' => $theirs['code'], 'state' => $mine['state']]));
$report['by-address-with-a-second-factor'] = $seen($omniauth->verify('oauth', $context, $trip(['sub' => '2002', 'email' => 'paul@example.org', 'email_verified' => true])));
$paul->identities['google'] = '2002';
$report['second-factor'] = $seen($omniauth->verify('oauth', $context, $trip(['sub' => '2002'])));
$omniauth->begin('email-code', $context);
$report['then-the-code'] = $seen($omniauth->verify('email-code', $context, ['code' => $sender->last()->secret]));

// Google itself, through league/oauth2-google and Guzzle, its answers recorded.
$answers = new MockHandler();
$google = new GoogleProvider('client.apps.googleusercontent.com', 'secret', 'https://example.org/login/google/callback', clock: $clock, collaborators: ['httpClient' => new Client(['handler' => HandlerStack::create($answers)])]);
$omniauth = $build($google);
$url = $omniauth->begin('oauth', $context)->payload;
parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
$jwt = static fn (array $claims) => implode('.', [Authorization::base64url('{"alg":"RS256","typ":"JWT"}'), Authorization::base64url(json_encode($claims)), Authorization::base64url(random_bytes(64))]);
$answers->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(['access_token' => 'ya29.x', 'expires_in' => 3599, 'token_type' => 'Bearer', 'id_token' => $jwt([
    'iss' => 'https://accounts.google.com', 'aud' => 'client.apps.googleusercontent.com', 'sub' => '108204', 'email' => 'ringo@example.org', 'email_verified' => true,
    'nonce' => $query['nonce'], 'iat' => 1792584000, 'exp' => 1792587600,
])])));
$report['google'] = $seen($omniauth->verify('oauth', $context, ['code' => '4/0AQ', 'state' => $query['state']])) + ['host' => parse_url($url, PHP_URL_HOST)];

$report['loaded'] = [
    'symbols' => [...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()],
    'files' => array_map('realpath', get_included_files()),
    'eager' => array_map('realpath', array_values(is_file($files = dirname($autoload).'/composer/autoload_files.php') ? require $files : [])),
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
