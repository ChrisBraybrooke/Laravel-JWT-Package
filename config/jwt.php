<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT UUID Key
    |--------------------------------------------------------------------------
    |
    | This should be the column name where you are storing the users UUID which
    | is returned from the authentication server in your local database. This
    | package DOES NOT create this columnm, you will have to do this yourself
    | or use a column you already have setup.
    |
    */

    'jwt_uuid_key' => 'auth_uuid',

    /*
    |--------------------------------------------------------------------------
    | Create New Users
    |--------------------------------------------------------------------------
    |
    | If a JWT is provided from the authentication server for which we don't
    | have a user in the local database, should we create a new user?
    |
    */

    'create_new_users' => true,

    /*
    |--------------------------------------------------------------------------
    | Auth Server Userinfo Endpoint
    |--------------------------------------------------------------------------
    |
    | If we are creating new users (option above), which api endpoint should we
    | call to fetch the user info.
    |
    */

    'auth_server_userinfo_endpoint' => env('OAUTH_AUTH_SERVER_API_ENDPOINT') . '/user',

    /*
    |--------------------------------------------------------------------------
    | Auth Server Userinfo Endpoint
    |--------------------------------------------------------------------------
    |
    | If we are creating new users (option above), which api endpoint should we
    | call to fetch the user info.
    |
    */

    'auth_server_client_check_endpoint' => env('OAUTH_AUTH_SERVER_API_ENDPOINT') . '/client-check',

    /*
    |--------------------------------------------------------------------------
    | Auth Public Key
    |--------------------------------------------------------------------------
    |
    | In order to validate the JWTs we need the public key that has been issued
    | by the authentication server.
    |
    */

    'auth_public_key' => env('OAUTH_PUBLIC_KEY')
];