<?php

namespace Omniauth\OAuth\Contract;

use Omniauth\OAuth\Identity;

/**
 * May an account be linked to an identity by its address alone - the
 * provider having said the address is verified, and no account linked to
 * that identity yet? Marco's decision QA3: never for an account that has a
 * second factor or an administration role (NoSecondFactorLinking says the
 * first; omnibase's rule, step AU4, adds its roles); the person then signs in
 * otherwise and links the provider from the account's settings.
 */
interface EmailLinking
{
    public function allows(object $account, Identity $identity): bool;
}
