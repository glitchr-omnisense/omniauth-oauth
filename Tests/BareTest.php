<?php

namespace Omniauth\OAuth\Tests;

use Omniauth\OAuth\OAuthMethod;
use Omniauth\Omniauth;
use PHPUnit\Framework\TestCase;

/**
 * omniauth/oauth with no framework: in PHP processes of their own (this one
 * has loaded PHPUnit), whole sign-ins by hand - a fake Google, then Google
 * over league/oauth2-google with recorded answers - and every class of the
 * package loaded. Nothing may come from outside but omniauth,
 * league/oauth2-client and league/oauth2-google, Guzzle (league's HTTP
 * client: guzzle, psr7, promises, getallheaders), the PSR interfaces and
 * symfony/password-hasher - no class of a framework, of hwi/oauth-bundle, of
 * the other omniauth packages or of an application.
 */
final class BareTest extends TestCase
{
    private const FOREIGN = '~^(?:Symfony\\\\(?!Component\\\\PasswordHasher\\\\|Polyfill\\\\)|Omniauth\\\\(?:Passkey|Totp)\\\\|(?:Illuminate|Laravel|Doctrine|Twig|Scheb|Lcobucci|Webauthn|OTPHP|HWI|Omnibridge|Base|App)\\\\)~';
    private const ALLOWED_FILES = '~/vendor/(?:psr/[\w-]+|symfony/(?:password-hasher|polyfill-[\w-]+|deprecation-contracts)|league/(?:oauth2-client|oauth2-google)|guzzlehttp/(?:guzzle|psr7|promises)|ralouphie/getallheaders|composer)/|/vendor/autoload\.php$~';

    public function testSignInsByHandLoadNothingElse(): void
    {
        $report = self::php([__DIR__.'/Fixtures/bare.php', self::autoload()]);

        self::assertSame(['authenticated', 'ringo', ['oauth']], [$report['linked']['status'], $report['linked']['account'], $report['linked']['passed']], 'a verified address links');
        self::assertSame(['google' => '108204'], $report['identities']);
        self::assertSame(['authenticated', 'ringo'], [$report['by-subject']['status'], $report['by-subject']['account']], 'then the subject alone');
        self::assertSame(['identity-unknown', null, ['9001', 'john@example.org', true]], [$report['unknown']['status'], $report['unknown']['account'], $report['unknown']['identity']], 'no account made');
        self::assertSame('identity-unknown', $report['unverified']['status'], 'an unverified address finds no account');
        self::assertSame(['failed', 'bad-credentials', 'state-mismatch'], [$report['forged']['status'], $report['forged']['failure'], $report['forged']['reason']]);
        self::assertSame(['failed', 'bad-credentials', 'exchange-failed'], [$report['injected']['status'], $report['injected']['failure'], $report['injected']['reason']], 'PKCE');
        self::assertSame(['failed', 'not-enrolled', 'link-from-settings'], [$report['by-address-with-a-second-factor']['status'], $report['by-address-with-a-second-factor']['failure'], $report['by-address-with-a-second-factor']['reason']], 'QA3');
        self::assertSame(['second-factor-required', ['oauth'], ['email-code']], [$report['second-factor']['status'], $report['second-factor']['passed'], $report['second-factor']['offered']], 'QA2');
        self::assertSame(['authenticated', ['oauth', 'email-code']], [$report['then-the-code']['status'], $report['then-the-code']['passed']]);
        self::assertSame(['authenticated', 'ringo', 'accounts.google.com'], [$report['google']['status'], $report['google']['account'], $report['google']['host']]);

        self::assertContains(OAuthMethod::class, $report['loaded']['symbols']);
        self::assertContains('League\OAuth2\Client\Provider\Google', $report['loaded']['symbols']);
        self::assertSame([], self::foreign($report['loaded']['symbols']));
        self::assertSame([], self::outside($report['loaded']['files'], $report['loaded']['eager']));
    }

    public function testEveryClassLoadsWithTheRequiredPackagesAlone(): void
    {
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\OAuth']);

        foreach (['OAuthMethod', 'Provider\GoogleProvider', 'Provider\Providers', 'Testing\FakeProvider', 'NoSecondFactorLinking'] as $class) {
            self::assertContains('Omniauth\OAuth\\'.$class, $report['loaded']);
        }
        self::assertSame([], self::foreign($report['symbols']));
        self::assertSame([], self::outside($report['files'], $report['eager']));
    }

    /** The check is not blind: a class of another omniauth package, once loaded, is seen. */
    public function testTheReportSeesWhatIsLoaded(): void
    {
        $other = 'Omniauth\Totp\TotpMethod';
        if (!class_exists($other)) {
            self::markTestSkipped('omniauth/totp is not installed beside.');
        }
        $report = self::php([__DIR__.'/Fixtures/load-all.php', self::autoload(), \dirname(__DIR__), 'Omniauth\OAuth', $other]);

        self::assertContains($other, self::foreign($report['symbols']));
    }

    /** @return list<string> */
    private static function foreign(array $symbols): array
    {
        return array_values(preg_grep(self::FOREIGN, $symbols));
    }

    /**
     * The files loaded from outside this package, omniauth's core and the
     * libraries allowed - but those Composer includes for every package at
     * start (autoload "files"), which say nothing of what this one uses.
     *
     * @return list<string>
     */
    private static function outside(array $files, array $eager): array
    {
        $roots = [realpath(\dirname(__DIR__)).'/', realpath(\dirname((string) (new \ReflectionClass(Omniauth::class))->getFileName())).'/'];
        $eager = array_map('dirname', array_filter($eager));

        return array_values(array_filter($files, static fn (?string $file) => null !== $file
            && [] === array_filter($roots, static fn (string $root) => str_starts_with($file, $root))
            && !\in_array(\dirname($file), $eager, true)
            && !preg_match(self::ALLOWED_FILES, $file)));
    }

    /** The autoloader that knows this package and its tests. */
    private static function autoload(): string
    {
        foreach (\Composer\Autoload\ClassLoader::getRegisteredLoaders() as $vendor => $loader) {
            if ($loader->findFile(OAuthMethod::class) && $loader->findFile(Fixtures\Kit::class)) {
                return $vendor.'/autoload.php';
            }
        }
        self::markTestSkipped('No autoloader knows omniauth/oauth\'s tests.');
    }

    /** @return array<string, mixed> */
    private static function php(array $arguments): array
    {
        $process = proc_open([\PHP_BINARY, ...$arguments], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        $status = proc_close($process);
        $report = json_decode($out, true);
        self::assertSame(0, $status, $err.$out);
        self::assertIsArray($report, $err.$out);

        return $report;
    }
}
