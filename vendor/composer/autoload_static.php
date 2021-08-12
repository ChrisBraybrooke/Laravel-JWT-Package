<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit6364cd0959888ed38729bd01a687e83b
{
    public static $prefixLengthsPsr4 = array (
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
        'C' => 
        array (
            'ChrisBraybrooke\\JWT\\' => 20,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
        'ChrisBraybrooke\\JWT\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit6364cd0959888ed38729bd01a687e83b::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit6364cd0959888ed38729bd01a687e83b::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit6364cd0959888ed38729bd01a687e83b::$classMap;

        }, null, ClassLoader::class);
    }
}
