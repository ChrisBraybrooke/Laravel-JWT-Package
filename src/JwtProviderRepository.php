<?php

namespace Velogik\CognitoAuth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtProviderRepository
{
    /**
     * The eloquent user provider.
     * 
     * @var \Illuminate\Auth\EloquentUserProvider
     */
    protected $provider;

    /**
     * Kick things off!
     *
     * @param EloquentUserProvider $provider
     */
    public function __construct(EloquentUserProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * Get the user from our local DB.
     * 
     * @param string $uuid
     * @return \Illuminate\Contracts\Auth\Authenticatable\Authenticatable | null
     */
    public function getJWTUser(string $uuid): ?Authenticatable
    {
        $model = $this->provider->createModel();
        $user = $model->where(config('cognito.auth_id_key'), $uuid)->first();

        if ($user) {
            return $user;
        } elseif (config('cognito.create_new_users') && method_exists($model, 'createFromAuthServer')) {
            return $model->createFromAuthServer(
                request()->bearerToken()
            );
        }

        return null;
    }
}