<?php

namespace ChrisBraybrooke\JWT\Traits;

use ChrisBraybrooke\JWT\Exceptions\AuthServerResponseError;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;

trait AuthenticatesWithAuthServer
{
    /**
     * Retrieve the user info from the auth server.
     *
     * @param  string $bearerToken
     * @return array
     */
    public function getUserInfoFromAuthServer($bearerToken)
    {
        $response = Http::withOptions(['verify' => false])
            ->withToken($bearerToken)
            ->get(config('jwt.auth_server_userinfo_endpoint'));

        throw_if($response->failed(), new AuthServerResponseError('Issue reaching authentication server!'));

        return $response->json();
    }

    /**
     * Create a user in the local DB from user info on the auth server.
     * 
     * @param  string $bearerToken
     * @return \App\User
     */
    public function createFromAuthServer($bearerToken)
    {
        $userInfo = $this->getUserInfoFromAuthServer($bearerToken);

        throw_if(!$userInfo['id'], new AuthServerResponseError('No user ID returned from authentication server!'));

        return $this->create(
            array_merge(
                Arr::except($userInfo, ['id']),
                [config('jwt.jwt_uuid_key') => $userInfo['id']]
            )
        );
    }
}