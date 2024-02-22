<?php

namespace Velogik\CognitoAuth\Traits;

use Velogik\CognitoAuth\Exceptions\AuthServerResponseError;
use Velogik\CognitoAuth\JwtTokenService;
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
    public function getUserInfoFromAuthServer($bearerToken): array
    {
        $cognito = \AWS::createClient('cognito-idp');
        $user = $cognito->getUser([
            'AccessToken' => $bearerToken
        ]);

        dd($user);

        return $this->authServerUserInfo($user);
    }

    /**
     * Manipulate the auth server user info response.
     *
     * @param  array $response
     * @return array
     */
    public function authServerUserInfo($response)
    {
        return $response;
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