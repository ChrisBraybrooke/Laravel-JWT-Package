<?php

namespace Velogik\CognitoAuth\Traits;

use Velogik\CognitoAuth\Exceptions\AuthServerResponseError;
use Velogik\CognitoAuth\JwtTokenService;
use Illuminate\Support\Arr;
use Aws\Result;

trait AuthenticatesWithCognito
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
     * @return \App\Models\User
     */
    public function createFromAuthServer($bearerToken)
    {
        $userInfo = $this->getUserInfoFromAuthServer($bearerToken);

        throw_if(!$userInfo['id'], new AuthServerResponseError('No user ID returned from authentication server!'));

        return $this->create(
            array_merge(
                Arr::except($userInfo, ['id']),
                [config('cognito.auth_id_key') => $userInfo['id']]
            )
        );
    }

    /**
     * Determine whether the users current token has a particular scope.
     * 
     * @param  string $scope
     * @return bool
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

    /**
     * Create the local user within Cognito.
     * 
     * @return \App\Models\User
     */
    public function createCognitoUser(array $attributes, string $password = null): Result
    {
        $cognito = \AWS::createClient('CognitoIdentityProvider');
        $obj = [
            'UserPoolId' => config('services.cognito.user_pool_id'),
            'Username' => $attributes['username'],
            'UserAttributes' => [
                [
                    'Name' => 'given_name',
                    'Value' => $attributes['given_name']
                ],
                [
                    'Name' => 'family_name',
                    'Value' => $attributes['family_name']
                ],
                [
                    'Name' => 'email',
                    'Value' => $attributes['email']
                ],
                // [
                //     'Name' => 'phone_number',
                //     'Value' => $attributes['phone_number']
                // ],
                [
                    'Name' => 'locale',
                    'Value' => $attributes['locale']
                ],
                [
                    'Name' => 'name',
                    'Value' => $attributes['name']
                ]
            ]
        ];

        if ($password) {
            $obj['TemporaryPassword'] = $password;
        }

        return $cognito->adminCreateUser($obj);
    }
}