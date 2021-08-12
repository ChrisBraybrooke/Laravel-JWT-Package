# Laravel Resource Server JWT Auth
For use with an authentication server using Laravel Passport. This package will read the incoming JWT and authenticate the user.

## Installation

```
composer require chrisbraybrooke/jwt
```

## Setup
1. Add the `ChrisBraybrooke\JWT\Traits\AuthenticatesWithAuthServer` trait to your `User` model, this contains a few methods that help create new users.

2. In your `.env` file add an `OAUTH_AUTH_SERVER_API_ENDPOINT` entry, this is the base api url on your authentication server, and will be used to pull the users information in when creating a new user. You also need a `OAUTH_PUBLIC_KEY` entry, this is your public key that is being used on the authentication server and will allow us to validate incoming JWTs.

3. Finally, you will need to change the api guard driver in your `config/auth.php` file - see below.

```
'api' => [
    'driver' => 'jwt', // --> We have created a driver called jwt, make sure your driver is set to this.
    'provider' => 'users',
    'hash' => false,
]
```

## Config
You can publish the config file be running `php artisan vendor:publish --tag=jwt-config`
