<?php

namespace Omniauth\OAuth\Tests;

use Omniauth\ArrayState;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Method\Methods;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\NoSecondFactorLinking;
use Omniauth\OAuth\Tests\Fixtures\Kit;
use Omniauth\OAuth\Testing\FakeProvider;
use Omniauth\Omniauth;
use Omniauth\Status;
use Omniauth\Testing\TestAccount;
use PHPUnit\Framework\TestCase;

/** The sign-in through a provider, its trip and its linking rule (QA3), through the conductor. */
final class OAuthMethodTest extends TestCase
{
    private const RINGO = ['sub' => '108204', 'email' => 'ringo@example.org', 'email_verified' => true, 'name' => 'Ringo Starr'];

    public function testTheTripOutCarriesTheStateTheChallengeAndTheNonceAndKeepsTheVerifier(): void
    {
        $kit = new Kit();
        $url = $kit->depart();
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        $kept = $kit->session[Omniauth::ATTEMPT]['kept']['oauth'];

        self::assertStringStartsWith(FakeProvider::AUTHORIZE.'?', $url);
        self::assertSame(['provider', 'state', 'verifier', 'nonce'], array_keys($kept));
        self::assertSame('google', $kept['provider']);
        self::assertSame($kept['state'], $query['state']);
        self::assertSame($kept['nonce'], $query['nonce']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame((new Authorization($kept['state'], $kept['verifier'], $kept['nonce']))->challenge(), $query['code_challenge']);
        self::assertStringNotContainsString($kept['verifier'], $url, 'the verifier never leaves the server');
        self::assertSame(43, \strlen($kept['verifier']));
        self::assertMatchesRegularExpression('~^[A-Za-z0-9_-]{43}$~', $kept['state']);
        self::assertSame('https://example.org/login/google/callback', $query['redirect_uri'], 'the return address is the configuration\'s');

        $again = $kit->depart();
        self::assertNotSame($kept['state'], $kit->session[Omniauth::ATTEMPT]['kept']['oauth']['state'], 'a new trip, new values');
        self::assertNotSame($url, $again);
    }

    public function testTheAccountLinkedToTheSubjectSignsInWhateverItsAddressSays(): void
    {
        $kit = new Kit();
        $kit->ringo->identities['google'] = '108204';
        $result = $kit->signIn(['sub' => '108204', 'email' => 'someone-else@example.net', 'email_verified' => false]);

        self::assertTrue($result->isAuthenticated());
        self::assertSame($kit->ringo, $result->account);
        self::assertSame([Factor::OAuth], $result->passed);
        self::assertArrayNotHasKey(Omniauth::ATTEMPT, $kit->session, 'cleared');
    }

    public function testAVerifiedAddressLinksItsAccountThenTheSubjectAlone(): void
    {
        $kit = new Kit();
        $result = $kit->signIn(self::RINGO);

        self::assertTrue($result->isAuthenticated());
        self::assertSame($kit->ringo, $result->account);
        self::assertSame(['google' => '108204'], $kit->ringo->identities, 'linked by its subject');

        // The address changed at Google since: the subject still finds ringo.
        $kit->omniauth->abandon();
        self::assertSame($kit->ringo, $kit->signIn(['sub' => '108204', 'email' => 'starr@example.net', 'email_verified' => true])->account);
    }

    public function testTheAddressIsComparedWithoutItsCase(): void
    {
        $kit = new Kit();

        self::assertSame($kit->ringo, $kit->signIn(['email' => 'Ringo@Example.ORG'] + self::RINGO)->account);
    }

    public function testAnAddressTheProviderDoesNotVouchForLinksNothing(): void
    {
        foreach ([false, 'false', null] as $verified) {
            $kit = new Kit();
            $person = ['email_verified' => $verified] + self::RINGO;
            if (null === $verified) {
                unset($person['email_verified']);
            }
            $result = $kit->signIn($person);

            self::assertSame(Status::IdentityUnknown, $result->status, var_export($verified, true));
            self::assertNull($result->account);
            self::assertSame([], $kit->ringo->identities, 'ringo is not linked');
            self::assertFalse($result->identity->emailVerified, 'the sign-up form knows the address is not proved');
        }
    }

    public function testTheStringTrueIsAVerifiedAddress(): void
    {
        $kit = new Kit();

        self::assertSame($kit->ringo, $kit->signIn(['email_verified' => 'true'] + self::RINGO)->account);
    }

    public function testAnUnknownIdentityIsAResultNotAnAccountAndTheSignUpAdoptsIt(): void
    {
        $kit = new Kit();
        $result = $kit->signIn(['sub' => '9001', 'email' => 'john@example.org', 'email_verified' => true, 'name' => 'John Lennon']);

        // lesringostars today: a transient account, then a 500 "User identifier is NULL" (AU0). Here: a result.
        self::assertSame(Status::IdentityUnknown, $result->status);
        self::assertNull($result->account);
        self::assertNull($result->failure);
        self::assertSame(['google', '9001', 'john@example.org', true, 'John Lennon'], [$result->identity->provider, $result->identity->subject, $result->identity->email, $result->identity->emailVerified, $result->identity->name]);
        self::assertArrayNotHasKey(Omniauth::ATTEMPT, $kit->session, 'nothing half signed in');
        self::assertNull($kit->store->byIdentifier('john@example.org'), 'no account created');

        // The host's sign-up made the account from what it kept of the result, then adopts the identity.
        $john = $kit->store->add(new TestAccount('5', 'john', 'john@example.org', name: 'John Lennon'));
        self::assertTrue($kit->oauth->adopt($john, $result->identity)->isDone());
        self::assertSame(['google' => '9001'], $john->identities);
        self::assertSame($john, $kit->signIn(['sub' => '9001'])->account);
        self::assertSame('linked-elsewhere', $kit->oauth->adopt($kit->ringo, $result->identity)->reason, 'one subject, one account');
    }

    public function testAUserNameThatLooksLikeTheAddressIsNotTheAccountsAddress(): void
    {
        $kit = new Kit();
        // george's user name is "harrison@example.org"; his address is george@example.org.
        $result = $kit->signIn(['sub' => '77', 'email' => 'harrison@example.org', 'email_verified' => true]);

        self::assertSame(Status::IdentityUnknown, $result->status);
        self::assertSame([], $kit->george->identities);
    }

    public function testASecondFactorFollowsGoogle(): void
    {
        $kit = new Kit();
        $kit->paul->identities['google'] = '2002';
        $result = $kit->signIn(['sub' => '2002']);

        self::assertSame(Status::SecondFactorRequired, $result->status);
        self::assertSame($kit->paul, $result->account);
        self::assertSame([Factor::OAuth], $result->passed);
        self::assertSame([Factor::EmailCode], $result->offered);

        $kit->omniauth->begin('email-code', Kit::context());
        $done = $kit->omniauth->verify('email-code', Kit::context(), ['code' => $kit->sender->last()->secret]);
        self::assertTrue($done->isAuthenticated());
        self::assertSame([Factor::OAuth, Factor::EmailCode], $done->passed);
    }

    public function testAnAccountWithASecondFactorIsNotLinkedByItsAddress(): void
    {
        $kit = new Kit(static fn (Methods $methods) => new NoSecondFactorLinking($methods));
        $result = $kit->signIn(['sub' => '2002', 'email' => 'paul@example.org', 'email_verified' => true]);

        self::assertSame(Status::Failed, $result->status);
        self::assertSame(Failure::NotEnrolled, $result->failure);
        self::assertSame('link-from-settings', $result->reason);
        self::assertSame([], $kit->paul->identities);

        // ringo has no second factor: his address links him.
        $kit->omniauth->abandon();
        self::assertSame($kit->ringo, $kit->signIn(self::RINGO)->account);
    }

    public function testNoLinkingByAddressAtAll(): void
    {
        $kit = new Kit(false);
        $result = $kit->signIn(self::RINGO);

        self::assertSame(Status::IdentityUnknown, $result->status);
        self::assertSame([], $kit->ringo->identities);
    }

    public function testAnAddressDoesNotMoveALinkToAnotherSubject(): void
    {
        $kit = new Kit();
        $kit->ringo->identities['google'] = '108204';
        $result = $kit->signIn(['sub' => '666'] + self::RINGO);

        self::assertSame([Failure::NotEnrolled, 'link-from-settings'], [$result->failure, $result->reason]);
        self::assertSame(['google' => '108204'], $kit->ringo->identities);
    }

    public function testABannedAccountIsRefusedAfterTheProviderVouchedForIt(): void
    {
        $kit = new Kit();
        $kit->pete->identities['google'] = '3003';
        $result = $kit->signIn(['sub' => '3003']);

        self::assertSame([Status::Failed, Failure::AccountRefused, 'banned'], [$result->status, $result->failure, $result->reason]);
    }

    public function testAForgedStateIsRefusedBeforeTheCodeIsExchanged(): void
    {
        $kit = new Kit();
        $url = $kit->depart();
        $return = $kit->google->consent($url, self::RINGO);
        $result = $kit->omniauth->verify('oauth', Kit::context(), ['state' => 'forged'] + $return);

        self::assertSame([Failure::BadCredentials, 'state-mismatch'], [$result->failure, $result->reason]);
        self::assertSame([], $kit->google->exchanges, 'no exchange');
        self::assertSame([], $kit->ringo->identities);
        // What the trip kept is gone with it: the honest return finds nothing to compare against.
        self::assertSame(Failure::Expired, $kit->omniauth->verify('oauth', Kit::context(), $return)->failure);
    }

    public function testAMissingStateIsAForgedOne(): void
    {
        $kit = new Kit();
        $return = $kit->google->consent($kit->depart(), self::RINGO);
        unset($return['state']);

        self::assertSame('state-mismatch', $kit->omniauth->verify('oauth', Kit::context(), $return)->reason);
    }

    public function testAReturnThisVisitorNeverBeganIsRefused(): void
    {
        // The attacker began and consented in their own browser, then has the victim's browser land on the return address.
        $attacker = new Kit();
        $return = $attacker->google->consent($attacker->depart(), ['sub' => 'attacker', 'email' => 'mallory@example.org', 'email_verified' => true]);

        $victim = new Kit();
        self::assertSame(Failure::Expired, $victim->omniauth->verify('oauth', Kit::context(), $return)->failure, 'nothing begun');
        $victim->depart();
        self::assertSame('state-mismatch', $victim->omniauth->verify('oauth', Kit::context(), $return)->reason, 'begun, but not this trip');
    }

    public function testACodeInjectedIntoAnotherTripIsRefusedByPkce(): void
    {
        // A code the attacker obtained for their own trip (or stole), pasted into the victim's return with the victim's state.
        $kit = new Kit();
        $theirs = $kit->google->consent($kit->google->authorizationUrl(Authorization::fresh()), ['sub' => 'attacker', 'email' => 'ringo@example.org', 'email_verified' => true]);
        $url = $kit->depart();
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        $result = $kit->omniauth->verify('oauth', Kit::context(), ['code' => $theirs['code'], 'state' => $query['state']]);

        self::assertSame([Failure::BadCredentials, 'exchange-failed'], [$result->failure, $result->reason]);
        self::assertCount(1, $kit->google->exchanges, 'exchanged with the verifier of this trip, which is not the code\'s');
        self::assertSame([], $kit->ringo->identities);
    }

    public function testAReturnServesOnce(): void
    {
        $kit = new Kit();
        $return = $kit->google->consent($kit->depart(), self::RINGO);
        self::assertTrue($kit->omniauth->verify('oauth', Kit::context(), $return)->isAuthenticated());

        self::assertSame(Failure::Expired, $kit->omniauth->verify('oauth', Kit::context(), $return)->failure);
    }

    public function testATripOlderThanTheAttemptIsGone(): void
    {
        $kit = new Kit();
        $return = $kit->google->consent($kit->depart(), self::RINGO);
        $kit->clock->advance(Omniauth::LIFETIME);

        self::assertSame(Failure::Expired, $kit->omniauth->verify('oauth', Kit::context(), $return)->failure);
    }

    public function testThePersonSaidNo(): void
    {
        $kit = new Kit();
        $result = $kit->omniauth->verify('oauth', Kit::context(), $kit->google->deny($kit->depart()));

        self::assertSame([Failure::BadCredentials, 'provider-denied'], [$result->failure, $result->reason]);
        $other = $kit->omniauth->verify('oauth', Kit::context(), ['error' => 'server_error'] + $kit->google->deny($kit->depart()));
        self::assertSame('provider-error', $other->reason);
        self::assertSame('missing-code', $kit->omniauth->verify('oauth', Kit::context(), ['state' => $kit->google->consent($kit->depart(), self::RINGO)['state']])->reason);
    }

    public function testAnotherProvidersReturnIsRefused(): void
    {
        $facebook = new FakeProvider('facebook', 'https://example.org/connect/facebook-check');
        $kit = new Kit(more: [$facebook]);
        $return = $kit->google->consent($kit->depart('google'), self::RINGO);

        self::assertSame('state-mismatch', $kit->omniauth->verify('oauth', Kit::context(), ['provider' => 'facebook'] + $return)->reason);
    }

    public function testAProviderNotServedIsRefusedAtTheBeginning(): void
    {
        $kit = new Kit(more: [new FakeProvider('facebook', 'https://example.org/connect/facebook-check')]);
        $challenge = $kit->omniauth->begin('oauth', Kit::context(), ['provider' => 'twitch']);

        self::assertTrue($challenge->hasFailed());
        self::assertSame('unknown-provider', $challenge->reason);
        self::assertTrue($kit->omniauth->begin('oauth', Kit::context())->hasFailed(), 'two providers: one must be named');
        self::assertSame('redirect', (new Kit())->omniauth->begin('oauth', Kit::context())->kind, 'one provider: it is the one');
    }

    public function testTheTripCrossesRequestsAsArraysAlone(): void
    {
        $kit = new Kit();
        $return = $kit->google->consent($kit->depart(), self::RINGO);

        // The return is another request: the session serialised, a new conductor over it.
        $session = json_decode(json_encode($kit->session, \JSON_THROW_ON_ERROR), true);
        $next = new Omniauth($kit->store, $kit->methods, new ArrayState($session), clock: $kit->clock);

        self::assertSame($kit->ringo, $next->verify('oauth', Kit::context(), $return)->account);
    }

    public function testAProviderIsLinkedFromTheSettings(): void
    {
        $kit = new Kit(false);
        $enrolment = $kit->omniauth->enrol(Factor::OAuth, $kit->paul);
        $challenge = $enrolment->begin(Kit::context(), ['provider' => 'google']);
        self::assertSame('redirect', $challenge->kind);
        $return = $kit->google->consent($challenge->payload, ['sub' => '2002', 'email' => 'paul.mccartney@gmail.example', 'email_verified' => false]);

        self::assertTrue($enrolment->confirm(Kit::context(), $return)->isDone(), 'signed in already: the address does not matter');
        self::assertSame(['google' => '2002'], $kit->paul->identities);
        self::assertArrayNotHasKey(Omniauth::ATTEMPT, $kit->session, 'no sign-in attempt touched');

        // Then Google signs paul in - and his code by e-mail follows.
        self::assertSame(Status::SecondFactorRequired, $kit->signIn(['sub' => '2002'])->status);
    }

    public function testASubjectLinkedToAnotherAccountIsNotLinkedFromTheSettings(): void
    {
        $kit = new Kit();
        $kit->ringo->identities['google'] = '108204';
        $enrolment = $kit->omniauth->enrol(Factor::OAuth, $kit->paul);
        $return = $kit->google->consent($enrolment->begin(Kit::context())->payload, self::RINGO);
        $refused = $enrolment->confirm(Kit::context(), $return);

        self::assertSame([Failure::BadCredentials, 'linked-elsewhere'], [$refused->failure, $refused->reason]);
        self::assertSame([], $kit->paul->identities);

        $other = $kit->omniauth->enrol(Factor::OAuth, $kit->ringo);
        $refused = $other->confirm(Kit::context(), $kit->google->consent($other->begin(Kit::context())->payload, ['sub' => '5']));
        self::assertSame('other-identity', $refused->reason, 'one identity per provider and account');
    }

    public function testTheSettingsTripChecksItsStateToo(): void
    {
        $kit = new Kit();
        $enrolment = $kit->omniauth->enrol(Factor::OAuth, $kit->paul);
        $return = $kit->google->consent($enrolment->begin(Kit::context())->payload, ['sub' => '2002']);
        $refused = $enrolment->confirm(Kit::context(), ['state' => 'forged'] + $return);

        self::assertSame([Failure::BadCredentials, 'state-mismatch'], [$refused->failure, $refused->reason]);
        self::assertSame(Failure::Expired, $enrolment->confirm(Kit::context(), $return)->failure);
        self::assertSame([], $kit->paul->identities);
    }
}
