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
    | AWS Region
    |--------------------------------------------------------------------------
    |
    | The AWS region in which your Cognito user pool is located.
    |
    */

    'aws_region' => env('AWS_REGION', 'us-east-1'),

    /*
    |--------------------------------------------------------------------------
    | Cognito User Pool ID
    |--------------------------------------------------------------------------
    |
    | The ID of the Cognito user pool you want to use for authentication.
    |
    */

    'user_pool_id' => env('AWS_COGNITO_USER_POOL_ID', ''),
];