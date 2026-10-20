<?php

namespace Omniauth\OAuth\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Omniauth\OAuth\Authorization;
use Omniauth\OAuth\Exception\ProviderError;
use Omniauth\OAuth\Identity;

/**
 * Any league/oauth2-client provider (league/oauth2-facebook, a
 * GenericProvider on a provider's three addresses...): the authorization
 * address with the state and the S256 challenge omniauth drew, the code
 * exchanged with its verifier, the person read from the resource owner's
 * details through the access token. $fields names the details' keys: the
 * subject (its resource owner's getId() when null), the address, whether it
 * is verified (null: the provider says nothing, so it is not - no account is
 * ever linked by such an address), the name.
 *
 * PKCE is omniauth's, not league's: leave the league provider's "pkceMethod"
 * unset (it would draw a verifier of its own that no attempt keeps).
 */
class LeagueProvider implements Provider
{
    public const FIELDS = ['subject' => null, 'email' => 'email', 'verified' => null, 'name' => 'name'];

    /** @var array{subject: ?string, email: ?string, verified: ?string, name: ?string} */
    protected readonly array $fields;

    /**
     * @param list<string>                $scopes
     * @param array<string, string|null> $fields
     */
    public function __construct(
        protected readonly string $name,
        protected readonly AbstractProvider $league,
        protected readonly array $scopes = [],
        array $fields = [],
    ) {
        $this->fields = $fields + self::FIELDS;
    }

    public function name(): string
    {
        return $this->name;
    }

    /** The league provider underneath (its HTTP client, its options). */
    public function league(): AbstractProvider
    {
        return $this->league;
    }

    public function authorizationUrl(Authorization $authorization): string
    {
        $url = $this->league->getAuthorizationUrl($this->authorizationOptions($authorization));
        if (null !== $this->league->getPkceCode()) {
            throw new \LogicException(\sprintf('The league provider of "%s" draws its own PKCE verifier: leave its "pkceMethod" option unset, omniauth draws and keeps it.', $this->name));
        }

        return $url;
    }

    public function identify(string $code, Authorization $authorization): Identity
    {
        try {
            $token = $this->league->getAccessToken('authorization_code', ['code' => $code, 'code_verifier' => $authorization->verifier]);
        } catch (\Throwable $e) {
            throw new ProviderError(ProviderError::EXCHANGE, $e->getMessage(), $e);
        }

        return $this->identity($token, $authorization);
    }

    /** @return array<string, mixed> what the authorization address carries besides the client's own */
    protected function authorizationOptions(Authorization $authorization): array
    {
        $options = [
            'state' => $authorization->state,
            'code_challenge' => $authorization->challenge(),
            'code_challenge_method' => 'S256',
        ];
        if ($this->scopes) {
            $options['scope'] = $this->scopes;
        }

        return $options;
    }

    /** The person, from the resource owner's details. */
    protected function identity(AccessTokenInterface $token, Authorization $authorization): Identity
    {
        $details = $this->details($token);
        $subject = null !== $this->fields['subject'] ? ($details[$this->fields['subject']] ?? null) : ($details['__id'] ?? null);

        return $this->fromClaims($subject, $details);
    }

    /**
     * @return array<string, mixed> the resource owner's details; under "__id" its getId()
     *
     * @throws ProviderError
     */
    protected function details(AccessTokenInterface $token): array
    {
        if (!$token instanceof AccessToken) {
            throw new ProviderError(ProviderError::EXCHANGE, 'The league provider gave no access token.');
        }
        try {
            $owner = $this->league->getResourceOwner($token);
        } catch (\Throwable $e) {
            // league/oauth2-google's check of the hosted domain, on the userinfo.
            $hosted = $e instanceof \League\OAuth2\Client\Exception\HostedDomainException;

            throw new ProviderError($hosted ? ProviderError::HOSTED_DOMAIN : ProviderError::EXCHANGE, $e->getMessage(), $e);
        }

        return ['__id' => $owner->getId()] + $owner->toArray();
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @throws ProviderError
     */
    protected function fromClaims(mixed $subject, array $claims): Identity
    {
        if (!\is_scalar($subject) || '' === (string) $subject) {
            throw new ProviderError(ProviderError::SUBJECT, \sprintf('The "%s" profile has no subject.', $this->name));
        }
        $email = null !== $this->fields['email'] && \is_string($claims[$this->fields['email']] ?? null) && '' !== $claims[$this->fields['email']] ? $claims[$this->fields['email']] : null;
        $name = null !== $this->fields['name'] && \is_string($claims[$this->fields['name']] ?? null) && '' !== $claims[$this->fields['name']] ? $claims[$this->fields['name']] : null;
        $verified = null !== $email && null !== $this->fields['verified'] && Identity::verified($claims[$this->fields['verified']] ?? null);
        unset($claims['__id']);

        return new Identity($this->name, (string) $subject, $email, $verified, $name, $claims);
    }
}
