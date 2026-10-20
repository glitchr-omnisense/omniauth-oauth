<?php

namespace Omniauth\OAuth;

use Omniauth\Method\Methods;
use Omniauth\OAuth\Contract\EmailLinking;

/**
 * QA3's rule for the address: an account that set up a second factor
 * (an authenticator application, the code by e-mail) is not linked by its
 * address - whoever holds the provider's account would then be one factor
 * away from it for good. It reads the methods mounted, so it can be built
 * before the OAuth method is added to them.
 */
final readonly class NoSecondFactorLinking implements EmailLinking
{
    public function __construct(private Methods $methods)
    {
    }

    public function allows(object $account, Identity $identity): bool
    {
        foreach ($this->methods->secondFactors() as $method) {
            if ($method->enrolled($account)) {
                return false;
            }
        }

        return true;
    }
}
