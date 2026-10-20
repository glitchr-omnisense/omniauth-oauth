<?php

/*
 * Loads every class of the package (but its tests) with Composer's
 * autoloader, then prints what was loaded: BareTest's child process.
 * Arguments: the autoloader, the package's directory, its namespace, and
 * classes to load besides (the check that it is not blind).
 */
[, $autoload, $root, $namespace] = $argv;
require $autoload;
$root = realpath($root);
$loaded = [];
$iterator = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    static fn (SplFileInfo $file) => !in_array($file->getFilename(), ['Tests', 'docker', 'vendor', 'docs', '.git'], true),
));
foreach ($iterator as $file) {
    if ('php' !== $file->getExtension()) {
        continue;
    }
    $class = $namespace.'\\'.str_replace('/', '\\', substr($file->getPathname(), strlen($root) + 1, -4));
    if (class_exists($class) || interface_exists($class) || enum_exists($class) || trait_exists($class)) {
        $loaded[] = $class;
    }
}
foreach (array_slice($argv, 4) as $class) {
    class_exists($class);
}
echo json_encode([
    'loaded' => $loaded,
    'symbols' => [...get_declared_classes(), ...get_declared_interfaces(), ...get_declared_traits()],
    'files' => array_map('realpath', get_included_files()),
    'eager' => array_map('realpath', array_values(is_file($f = dirname($autoload).'/composer/autoload_files.php') ? require $f : [])),
], JSON_UNESCAPED_SLASHES);
