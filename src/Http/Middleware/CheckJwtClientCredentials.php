<?php

namespace ChrisBraybrooke\JWT\Http\Middleware;

use ChrisBraybrooke\JWT\Exceptions\AuthServerResponseError;
use ChrisBraybrooke\JWT\Exceptions\ClientRevokedError;
use ChrisBraybrooke\JWT\Exceptions\MissingScopeException;
use ChrisBraybrooke\JWT\JwtTokenService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpFoundation\Response;

class CheckJwtClientCredentials
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, ...$scopes): Response
    {
        $tokenService = new JwtTokenService;
        $jwt = $tokenService->getTokenFromRequest($request);

        if (! in_array('*', $tokenService->getScopesFromToken($jwt, false))) {
            foreach ($scopes as $scope) {
                if (! $tokenService->tokenCan($jwt, $scope, false)) {
                    throw new MissingScopeException($scope);
                }
            }
        }

        $this->checkTokenHasNotBeenRevoked(
            $tokenService->decode($jwt, false)->jti,
            $jwt
        );

        return $next($request);
    }

    /**
     * Check with the authentication server that this token has not been revoked.
     * 
     * @param $id string
     * @param $jwt string
     */
    protected function checkTokenHasNotBeenRevoked($id, $jwt)
    {
        $response = Http::withOptions(['verify' => config('app.env') === 'production'])
            ->withToken($jwt)
            ->post(config('jwt.auth_server_client_check_endpoint'), [
                'id' => $id
            ]);

        if ($response->successful()) {
            if ($response->json()['valid'] ?? false) {
                return;
            }
        } else {
            throw new AuthServerResponseError('Cannot verify client revocation status with auth server!');
        }

        throw new ClientRevokedError('Client has been revoked!');
    }
}
