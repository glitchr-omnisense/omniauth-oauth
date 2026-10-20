<?php

namespace Omniauth\OAuth\Tests\Fixtures;

use Omniauth\ArrayState;
use Omniauth\CacheThrottle;
use Omniauth\Context;
use Omniauth\EmailCode\EmailCodeMethod;
use Omniauth\Method\Methods;
use Omniauth\OAuth\Contract\EmailLinking;
use Omniauth\OAuth\OAuthMethod;
use Omniauth\OAuth\Provider\Provider;
use Omniauth\OAuth\Provider\Providers;
use Omniauth\OAuth\Testing\FakeProvider;
use Omniauth\Omniauth;
use Omniauth\Password\PasswordMethod;
use Omniauth\Result;
use Omniauth\Testing\ArrayCache;
use Omniauth\Testing\FixedClock;
use Omniauth\Testing\InMemoryStore;
use Omniauth\Testing\RecordingSender;
use Omniauth\Testing\TestAccount;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

/**
 * omniauth with an identity provider, on the in-memory stores: ringo (a
 * password); paul (a password and the code by e-mail: a second factor); pete
 * (banned); george, whose user name is an address that is not his. A fake
 * Google unless told, a fixed clock, a throttle, a recording sender.
 */
final class Kit
{
    public const SECRET = 'a-kernel-secret-of-thirty-two-bytes-or-more';

    public readonly FixedClock $clock;
    public readonly InMemoryStore $store;
    public readonly RecordingSender $sender;
    public readonly Methods $methods;
    public readonly OAuthMethod $oauth;
    public readonly FakeProvider $google;
    public readonly TestAccount $ringo;
    public readonly TestAccount $paul;
    public readonly TestAccount $pete;
    public readonly TestAccount $george;
    public readonly Omniauth $omniauth;
    /** @var array<string, mixed> */
    public array $session = [];

    /**
     * @param EmailLinking|bool|\Closure(Methods): EmailLinking $byEmail
     * @param list<Provider>                                       $more providers beside the fake Google
     */
    public function __construct(EmailLinking|bool|\Closure $byEmail = true, array $more = [], ?Provider $google = null)
    {
        $this->clock = new FixedClock('2026-10-21 12:00:00 UTC');
        $this->sender = new RecordingSender();
        $hasher = new NativePasswordHasher(cost: 4);
        $this->store = new InMemoryStore(
            $this->ringo = new TestAccount('1', 'ringo', 'ringo@example.org', $hasher->hash('yellow-submarine'), 'Ringo Starr'),
            $this->paul = new TestAccount('2', 'paul', 'paul@example.org', $hasher->hash('let-it-be'), 'Paul', emailCodeEnabled: true),
            $this->pete = new TestAccount('3', 'pete', 'pete@example.org', $hasher->hash('love-me-do'), 'Pete', refused: 'banned'),
            $this->george = new TestAccount('4', 'harrison@example.org', 'george@example.org', $hasher->hash('something'), 'George'),
        );
        $this->google = new FakeProvider('google');
        $this->methods = new Methods([
            new PasswordMethod($this->store, $this->store, $hasher),
            new EmailCodeMethod($this->store, $this->store->emailCodes(), $this->sender, self::SECRET, clock: $this->clock),
        ]);
        $this->oauth = new OAuthMethod($this->store, $this->store, new Providers($google ?? $this->google, ...$more), $byEmail instanceof \Closure ? $byEmail($this->methods) : $byEmail, $this->clock);
        $this->methods->add($this->oauth);
        $this->omniauth = new Omniauth(
            $this->store,
            $this->methods,
            new ArrayState($this->session),
            throttle: new CacheThrottle(new ArrayCache($this->clock), clock: $this->clock),
            clock: $this->clock,
        );
    }

    public static function context(): Context
    {
        return new Context('https://example.org', 'example.org', '203.0.113.7');
    }

    /** Begins at the sign-in page: the authorization address the visitor is sent to. */
    public function depart(string $provider = 'google'): string
    {
        $challenge = $this->omniauth->begin('oauth', self::context(), ['provider' => $provider]);
        if ('redirect' !== $challenge->kind) {
            throw new \RuntimeException('No authorization address: '.$challenge->reason);
        }

        return (string) $challenge->payload;
    }

    /** The whole trip: begin, the person consents at the fake Google, the return verified. */
    public function signIn(array $person, array $return = []): Result
    {
        return $this->omniauth->verify('oauth', self::context(), $return + $this->google->consent($this->depart(), $person));
    }
}
