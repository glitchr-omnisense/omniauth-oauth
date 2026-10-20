<?php

namespace Omniauth\OAuth\Exception;

use Omniauth\Exception\OmniauthException;

/**
 * The provider did not vouch for anyone: the code refused at the exchange, an
 * ID token not for this client, past its time or without the nonce, a profile
 * without its subject. $reason is the stable word the method answers with;
 * the message (and the previous exception: league's, Guzzle's) is for the
 * server's log, not the page.
 */
final class ProviderError extends \RuntimeException implements OmniauthException
{
    public const EXCHANGE = 'exchange-failed';
    public const ID_TOKEN = 'invalid-id-token';
    public const SUBJECT = 'no-subject';
    public const HOSTED_DOMAIN = 'hosted-domain';

    public function __construct(public readonly string $reason, string $message = '', ?\Throwable $previous = null)
    {
        parent::__construct('' !== $message ? $message : $reason, 0, $previous);
    }
}
