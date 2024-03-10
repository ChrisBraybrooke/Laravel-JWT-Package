<?php

namespace Velogik\CognitoAuth\Tests\Support;

trait CognitoAuthentication
{
    /**
     * The Cognito client.
     *
     * @param \Aws\CognitoIdentityProvider\CognitoIdentityProviderClient
     */
    protected $cognitoClient;

    /**
     * The username of the user.
     *
     * @param string
     */
    protected $username;

    /**
     * The access token.
     *
     * @param string
     */
    protected $accessToken;

    /**
     * The refresh token.
     *
     * @param string
     */
    protected $refreshToken;

    /**
     * Setup the Cognito client and get the access token.
     *
     * @return void
     */
    protected function setupCognito(): void
    {
        $this->afterApplicationCreated(function () {
            $this->cognitoClient = \AWS::createClient('CognitoIdentityProvider');
            $this->username = fake()->unique()->userName();
            $password = fake()->password(16, 18) . 'A1@';

            $this->createCogitoUser();
            $this->setPasswordAndConfirmUser(
                $password
            );
            $this->authenticateUserAndGetAccessToken(
                $password
            );
        });
    }

    /**
     * Tear down the Cognito user.
     *
     * @return void
     */
    protected function tearDownCognito(): void
    {
        $this->cognitoClient->adminDeleteUser([
            'UserPoolId' => config('services.cognito.user_pool_id'),
            'Username' => $this->username
        ]);
    }

    /**
     * Create a new Cognito user.
     *
     * @return void
     */
    protected function createCogitoUser()
    {
        $this->artisan('vgk:user', [
            '--first_name' => fake()->firstName(),
            '--last_name' => fake()->lastName(),
            '--username' => $this->username,
            '--email' => fake()->unique()->safeEmail(),
            '--phone' => fake()->phoneNumber(),
            '--locale' => 'en',
            '--tenant-id' => fake()->uuid()
        ]);
    }

    /**
     * Set the password and confirm the user.
     *
     * @param string $password
     * @return void
     */
    protected function setPasswordAndConfirmUser(string $password)
    {
        $this->cognitoClient->adminSetUserPassword([
            'Password' => $password,
            'Permanent' => true,
            'UserPoolId' => config('services.cognito.user_pool_id'),
            'Username' => $this->username
        ]);
    }

    /**
     * Authenticate the user and get the access token.
     *
     * @param string $password
     * @return void
     */
    protected function authenticateUserAndGetAccessToken(string $password)
    {
        $authenticationResponse = $this->cognitoClient->adminInitiateAuth([
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
            'ClientId' => config('services.cognito.admin_client_id'),
            'UserPoolId' => config('services.cognito.user_pool_id'),
            'AuthParameters' => [
                'SECRET_HASH' => base64_encode(
                    hash_hmac(
                        'sha256',
                        $this->username . config('services.cognito.admin_client_id'),
                        config('services.cognito.admin_client_secret'),
                        true
                    )
                ),
                'USERNAME' => $this->username,
                'PASSWORD' => $password
            ]
        ]);

        $this->accessToken = $authenticationResponse->search('AuthenticationResult.AccessToken');
        $this->refreshToken = $authenticationResponse->search('AuthenticationResult.RefreshToken');
    }
}