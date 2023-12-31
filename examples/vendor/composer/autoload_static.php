<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitc01b1cf286899859b11ac303393b7aad
{
    public static $prefixLengthsPsr4 = array (
        'C' => 
        array (
            'CrudeCrypto\\' => 12,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'CrudeCrypto\\' => 
        array (
            0 => __DIR__ . '/../..' . '/../src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitc01b1cf286899859b11ac303393b7aad::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitc01b1cf286899859b11ac303393b7aad::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitc01b1cf286899859b11ac303393b7aad::$classMap;

        }, null, ClassLoader::class);
    }
}
