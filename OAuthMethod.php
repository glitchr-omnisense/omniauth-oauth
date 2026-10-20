<?php

namespace Omniauth\OAuth;

use Omniauth\Attempt;
use Omniauth\Context;
use Omniauth\Contract\Accounts;
use Omniauth\Contract\Identities;
use Omniauth\Enrolled;
use Omniauth\Factor;
use Omniauth\Failure;
use Omniauth\Method\Challenge;
use Omniauth\Method\Challenging;
use Omniauth\Method\Enrolling;
use Omniauth\Method\Verdict;
use Omniauth\OAuth\Contract\EmailLinking;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Provider\Provider;
use Omniauth\OAuth\Provider\Providers;
use Omniauth\PendingIdentity;
use Omniauth\Proof;

/**
 * Signing in through an identity provider (OAuth 2, OpenID Connect), a first
 * factor: begin() draws a state, a PKCE verifier and a nonce, keeps them in
 * the attempt and answers with the provider's authorization address
 * (Challenge::redirect()); verify() takes the return's ['code' => …,
 * 'state' => …] (or its ['error' => …]), takes what the attempt kept - once:
 * a return comes back once -, compares the state in constant time, has the
 * provider exchange the code with the verifier and read the person (an ID
 * token or a userinfo, never the address's parameters), then finds the
 * account (Marco's decision QA3):
 *
 * 1. the account linked to that provider's subject ("sub"), whatever its
 *    address says now;
 * 2. else, only when the provider says the address is verified, the account
 *    of that address - linked there and then, unless $byEmail refuses it
 *    (false: never; an EmailLinking: NoSecondFactorLinking, omnibase's rule),
 *    and never an account already linked to another subject of that
 *    provider: then `not-enrolled` (reason `link-from-settings`): the person
 *    signs in otherwise and links the provider from the settings;
 * 3. else nobody: the conductor answers Status::IdentityUnknown with the
 *    PendingIdentity a sign-up form fills in - no account is ever created
 *    here (lesringostars' transient account and its 500 "User identifier is
 *    NULL" are gone); once the host has made the account, adopt() links it.
 *
 * Then the conductor does what it does after any first factor: the account
 * checked, and the second factor asked when the account has one (QA2:
 * EnrolledSecondFactors::AFTER holds OAuth).
 *
 * From the settings, enrolBegin()/enrolConfirm() link a provider to the
 * account signed in (['provider' => 'google']): the same trip, the subject
 * refused when another account holds it.
 *
 * Refusals are `bad-credentials` with a stable reason: `unknown-provider`,
 * `state-mismatch`, `provider-denied` (the person said no), `provider-error`,
 * `missing-code`, `exchange-failed` (a code refused - a PKCE verifier that is
 * not the code's among the causes), `invalid-id-token`, `no-subject`,
 * `hosted-domain`, `linked-elsewhere`, `other-identity`; and `expired` when
 * the attempt kept nothing (no beginning, a return replayed, ten minutes
 * gone).
 */
final class OAuthMethod implements Challenging, Enrolling
{
    public function __construct(
        private readonly Accounts $accounts,
        private readonly Identities $identities,
        private readonly Providers $providers,
        /** Link an account by a verified address: true (any), false (never), or a rule (QA3: NoSecondFactorLinking). */
        private readonly EmailLinking|bool $byEmail = true,
    ) {
    }

    public function factor(): Factor
    {
        return Factor::OAuth;
    }

    public function providers(): Providers
    {
        return $this->providers;
    }

    public function begin(Attempt $attempt, Proof $proof, Context $context): Challenge
    {
        return $this->depart($attempt, $proof);
    }

    public function verify(Attempt $attempt, Proof $proof, Context $context): Verdict
    {
        $returned = $this->returned($attempt, $proof);
        if (!$returned instanceof Identity) {
            return $returned;
        }
        $owner = $this->identities->owner($returned->provider, $returned->subject);
        if (null !== $owner) {
            return Verdict::passed($owner);
        }
        $account = $this->byVerifiedEmail($returned);
        if (null === $account) {
            return Verdict::unknown($returned->pending());
        }
        if (\in_array($returned->provider, $this->identities->providers($account), true)) {
            // The account is linked to another person at that provider: an address does not move a link.
            return Verdict::refused(Failure::NotEnrolled, 'link-from-settings');
        }
        if (false === $this->byEmail || ($this->byEmail instanceof EmailLinking && !$this->byEmail->allows($account, $returned))) {
            return Verdict::refused(Failure::NotEnrolled, 'link-from-settings');
        }
        $this->identities->link($account, $returned->provider, $returned->subject);

        return Verdict::passed($account);
    }

    public function enrolBegin(Attempt $enrolment, Proof $proof, Context $context): Challenge
    {
        return $this->depart($enrolment, $proof);
    }

    public function enrolConfirm(Attempt $enrolment, Proof $proof, Context $context): Enrolled
    {
        $account = $enrolment->account() ?? throw new \LogicException('An enrolment has its account.');
        $returned = $this->returned($enrolment, $proof);
        if (!$returned instanceof Identity) {
            return Enrolled::failed($returned->failure ?? Failure::BadCredentials, $returned->reason);
        }

        return $this->link($account, $returned->provider, $returned->subject);
    }

    /**
     * After a sign-up from Status::IdentityUnknown: links the new account to
     * the identity the result carried - as the host kept it on its side
     * (its session), never as a form posted it back.
     */
    public function adopt(object $account, PendingIdentity $identity): Enrolled
    {
        return $this->link($account, $identity->provider, $identity->subject);
    }

    private function link(object $account, string $provider, string $subject): Enrolled
    {
        $owner = $this->identities->owner($provider, $subject);
        if (null !== $owner) {
            return $this->accounts->handle($owner) === $this->accounts->handle($account) ? Enrolled::done() : Enrolled::failed(Failure::BadCredentials, 'linked-elsewhere');
        }
        if (\in_array($provider, $this->identities->providers($account), true)) {
            return Enrolled::failed(Failure::BadCredentials, 'other-identity');
        }
        $this->identities->link($account, $provider, $subject);

        return Enrolled::done();
    }

    /** The trip out: the provider named (or the only one), three values kept, its address given. */
    private function depart(Attempt $attempt, Proof $proof): Challenge
    {
        $provider = $this->provider($proof->string('provider'));
        if (null === $provider) {
            return Challenge::failed(Failure::BadCredentials, 'unknown-provider');
        }
        $authorization = Authorization::fresh();
        $attempt->keep(Factor::OAuth, ['provider' => $provider->name()] + $authorization->toArray());

        return Challenge::redirect($provider->authorizationUrl($authorization));
    }

    /** The trip back: the person, or why not. */
    private function returned(Attempt $attempt, Proof $proof): Identity|Verdict
    {
        $kept = $attempt->take(Factor::OAuth);
        $authorization = Authorization::fromArray($kept);
        $provider = \is_array($kept) && \is_string($kept['provider'] ?? null) ? $this->providers->get($kept['provider']) : null;
        if (null === $authorization || null === $provider) {
            return Verdict::expired();
        }
        if ($proof->has('provider') && $proof->string('provider') !== $provider->name()) {
            return Verdict::refused(Failure::BadCredentials, 'state-mismatch');
        }
        // Before anything else, the state: a return this visitor did not begin is not read further (login CSRF).
        if (!$authorization->matches($proof->string('state'))) {
            return Verdict::refused(Failure::BadCredentials, 'state-mismatch');
        }
        if ($proof->has('error')) {
            return Verdict::refused(Failure::BadCredentials, 'access_denied' === $proof->string('error') ? 'provider-denied' : 'provider-error');
        }
        $code = $proof->string('code');
        if ('' === $code) {
            return Verdict::refused(Failure::BadCredentials, 'missing-code');
        }
        try {
            $identity = $provider->identify($code, $authorization);
        } catch (ProviderError $e) {
            return Verdict::refused(Failure::BadCredentials, $e->reason);
        }
        if ($identity->provider !== $provider->name()) {
            throw new \LogicException(\sprintf('The "%s" provider vouched for an identity of "%s".', $provider->name(), $identity->provider));
        }

        return $identity;
    }

    /** The account of a verified address, if the method may look for it at all. */
    private function byVerifiedEmail(Identity $identity): ?object
    {
        if (false === $this->byEmail || !$identity->emailVerified || null === $identity->email) {
            return null;
        }
        $account = $this->accounts->byIdentifier($identity->email);
        $email = null !== $account ? $this->accounts->email($account) : null;

        // byIdentifier() may find a user name equal to the address: only the account's own address counts.
        return null !== $email && 0 === strcasecmp($email, $identity->email) ? $account : null;
    }

    private function provider(string $name): ?Provider
    {
        if ('' === $name) {
            return 1 === \count($this->providers) ? $this->providers->get($this->providers->names()[0]) : null;
        }

        return $this->providers->get($name);
    }
}
