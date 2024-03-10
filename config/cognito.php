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

    'auth_id_key' => 'cognito_id',

    /*
    |--------------------------------------------------------------------------
    | Create New Users
    |--------------------------------------------------------------------------
    |
    | If a JWT is provided from the authentication server for which we don't
    | have a user in the local database, should we create a new user?
    |
    */

    'create_new_users' => true
];