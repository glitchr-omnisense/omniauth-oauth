<?php

namespace Omniauth\OAuth\Provider;

/*
 * Omniauth\OAuth\Provider\LeagueProvider is now Omniauth\Google\LeagueProvider (omniauth/google):
 * one package per provider, and this one requires no OAuth library. The former
 * name is an alias of the new class for one release, when omniauth/google is
 * installed.
 *
 * @deprecated use Omniauth\Google\LeagueProvider (composer require omniauth/google)
 */
if (class_exists(\Omniauth\Google\LeagueProvider::class)) {
    @trigger_error('Omniauth\OAuth\Provider\LeagueProvider is deprecated: use Omniauth\Google\LeagueProvider (omniauth/google).', \E_USER_DEPRECATED);
    class_alias(\Omniauth\Google\LeagueProvider::class, LeagueProvider::class);
}
