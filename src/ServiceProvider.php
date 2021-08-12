<?php

namespace ChrisBraybrooke\JWT;

use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Illuminate\Support\Facades\Auth;

class ServiceProvider extends BaseServiceProvider
{
    /**
     * Bootstrap the package.
     *
     * @return void
     */
    public function boot()
    {
        $this->handleConfigs();

        Auth::extend('jwt', function ($app, $name, array $config) {
            return new JwtGuard(
                new JwtProviderRepository(
                    Auth::createUserProvider($config['provider'])                    
                ),
                $app['request']
            );
        });
    }

    /**
     * Register anything this package needs.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/jwt.php', 'jwt'
        );
    }

    /** 
     * Register any config files this package needs.
     *
     * @return void
     */
    private function handleConfigs()
    {
        $this->publishes([
            __DIR__.'/../config/jwt.php' => config_path('jwt.php')
        ], 'jwt-config');
    }
}
