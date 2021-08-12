<?php

namespace ChrisBraybrooke\JWT;

use ChrisBraybrooke\JWT\Exceptions\MethodNotSupportedException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request\Request
     */
    protected $request;

    /**
     * The provider repository instance.
     * 
     * @var \ChrisBraybrooke\JWT\JwtProviderRepository
     */
    protected $provider;

    /**
     * @param \ChrisBraybrooke\JWT\JwtProviderRepository
     * @param \Illuminate\Http\Request\Request  $request
     *
     * @return void
     */
    public function __construct(JwtProviderRepository $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request  = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @throws
     * @return Authenticatable|null
     */
    public function user()
    {
        if ($this->user  instanceof Authenticatable) {
            return $this->user;
        }

        $tokenService = new JwtTokenService;
        $jwt = $tokenService->getTokenFromRequest($this->request);

        if (!$jwt) {
            return null;
        }

        $uuid = $tokenService->getUuidFromToken($jwt);

        return $this->user = $this->provider->getJWTUser($uuid);
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function validate(array $credentials = []){
        throw new MethodNotSupportedException('JWT does not support the validate method.');
    }

    /**
     * @param  array  $credentials
     * @throws MethodNotSupportedException
     */
    public function attempt(array $credentials = [])
    {
        throw new MethodNotSupportedException('JWT does not support the attempt method.');
    }
}