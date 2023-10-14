<?php

namespace ChrisBraybrooke\JWT\Traits;

use ChrisBraybrooke\JWT\Exceptions\AuthServerResponseError;
use ChrisBraybrooke\JWT\JwtTokenService;
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
        $response = Http::withOptions(['verify' => config('app.env') === 'production'])
            ->withToken($bearerToken)
            ->get(config('jwt.auth_server_userinfo_endpoint'));

        throw_if($response->failed(), new AuthServerResponseError('Issue reaching authentication server!'));

        return $this->authServerUserInfo($response);
    }

    /**
     * Manipulate the auth server user info response.
     *
     * @param  Response $response
     * @return array
     */
    public function authServerUserInfo($response)
    {
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

    /**
     * Determine whether the users current token has a particular scope.
     * 
     * @param  string $scope
     * @return Boolean
     */
    public function tokenCan($scope)
    {
        $tokenService = new JwtTokenService;
        return $tokenService->tokenCan(
            $tokenService->getTokenFromRequest(
                request()
            ),
            $scope
        );
    }
}