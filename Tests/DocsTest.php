<?php

namespace Omniauth\OAuth\Tests;

use PHPUnit\Framework\TestCase;

/** docs/installation.md's PHP block, run as it is written (its autoloader the one of this run). */
final class DocsTest extends TestCase
{
    public function testTheInstallationPageRunsAsWritten(): void
    {
        $page = (string) file_get_contents(__DIR__.'/../docs/installation.md');
        self::assertSame(1, preg_match('~```php\n(.*?)```~s', $page, $block));
        $autoload = \dirname((string) (new \ReflectionClass(\Composer\Autoload\ClassLoader::class))->getFileName(), 2).'/autoload.php';
        $code = str_replace("require 'vendor/autoload.php';", 'require '.var_export($autoload, true).';', $block[1], $replaced);
        self::assertSame(1, $replaced);
        $script = tempnam(sys_get_temp_dir(), 'omniauth-oauth-docs');
        file_put_contents($script, $code);
        try {
            $process = proc_open([\PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $out = (string) stream_get_contents($pipes[1]);
            $err = (string) stream_get_contents($pipes[2]);
            self::assertSame(0, proc_close($process), $err.$out);
        } finally {
            unlink($script);
        }

        $lines = ['authenticated as ringo, linked to google 108204', 'identity-unknown: john@example.org'];
        self::assertSame(implode("\n", $lines)."\n", $out);
        foreach ($lines as $line) {
            self::assertStringContainsString("\n// $line\n", $block[1], 'the page says what it prints');
        }
    }
}
