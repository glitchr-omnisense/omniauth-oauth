<?php

namespace Omniauth\OAuth\Provider;

/*
 * Omniauth\OAuth\Provider\GoogleProvider is now Omniauth\Google\GoogleProvider (omniauth/google):
 * one package per provider, and this one requires no OAuth library. The former
 * name is an alias of the new class for one release, when omniauth/google is
 * installed.
 *
 * @deprecated use Omniauth\Google\GoogleProvider (composer require omniauth/google)
 */
if (class_exists(\Omniauth\Google\GoogleProvider::class)) {
    @trigger_error('Omniauth\OAuth\Provider\GoogleProvider is deprecated: use Omniauth\Google\GoogleProvider (omniauth/google).', \E_USER_DEPRECATED);
    class_alias(\Omniauth\Google\GoogleProvider::class, GoogleProvider::class);
}
