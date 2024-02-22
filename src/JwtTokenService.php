<?php

namespace Velogik\CognitoAuth;

use Velogik\CognitoAuth\Exceptions\InvalidTokenException;
use Doctrine\Instantiator\Exception\UnexpectedValueException;
use DomainException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Ramsey\Uuid\Uuid;
use CoderCat\JWKToPEM\JWKConverter;

class JwtTokenService
{
    /**
     * Extract the token from a request.
     *
     * @param  \Illuminate\Http\Request $request
     * @return string
     */
    public function getTokenFromRequest(Request $request): ?string
    {
        $jwt = $request->bearerToken();
        return $jwt;
    }

    /**
     * Get the users UUID from the token.
     * 
     * @param string $jwt
     * @return string
     * @throws InvalidTokenException|Throwable
     */
    public function getUuidFromToken(string $jwt): string
    {
        $payload = $this->decode($jwt);

        throw_unless($payload->sub, new InvalidTokenException('Uuid not found in JWT'));

        return $payload->sub;
    }

    /**
     * Get the scopes from the token
     * 
     * @param string $jwt
     * @return string
     * @throws InvalidTokenException|Throwable
     */
    public function getScopesFromToken(string $jwt, $validate = true): array
    {
        $payload = $this->decode($jwt, $validate);

        throw_unless(is_array($payload->scopes), new InvalidTokenException('Scopes not found in JWT'));

        return $payload->scopes;
    }

    /**
     * Determine whether the token has a specific scope.
     * 
     * @param string $jwt
     * @return bool
     */
    public function tokenCan(string $jwt, $scope, $validate = true): bool
    {
        if (array_key_exists($scope, array_flip($this->getScopesFromToken($jwt, $validate)))) {
            return true;
        }

        return false;
    }

    /**
     * Decode the JWT.
     * 
     * @param string $jwt
     * @return object
     * @throws InvalidTokenException
     */
    public function decode(string $jwt, $validate = true): object
    {
        $jwkConverter = new JWKConverter();

        $this->validateHeader($jwt);

        $pem = $jwkConverter->toPEM(
            $this->getJwk(
                $this->decodeHeader($jwt)->kid
            )
        );

        try {
            $payload = JWT::decode($jwt, $pem, ['RS256']);
        } catch (
            InvalidArgumentException
            | UnexpectedValueException
            | SignatureInvalidException
            | BeforeValidException
            | ExpiredException
            | DomainException
            $e
        ) {
            throw new InvalidTokenException($e->getMessage());
        }

        if ($validate) {
            $this->validatePayload($payload);
        }

        return $payload;
    }

    /**
     * Validates the header exists, can be base64 decoded, has a kid,
     * and has RS256 as alg
     *
     * @param string $jwt
     * @throws InvalidTokenException
     */
    public function validateHeader(string $jwt): void
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new InvalidTokenException('Wrong number of segments');
        }

        try {
            $header = $this->decodeHeader($jwt);
        } catch (DomainException $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        if (empty($header->kid)) {
            throw new InvalidTokenException('No kid present in token header');
        }

        if (empty($header->alg)) {
            throw new InvalidTokenException('No alg present in token header');
        }

        if ($header->alg !== 'RS256') {
            throw new InvalidTokenException('The token alg is not RS256');
        }
    }

    /**
     * Decode the header of the JWT.
     * 
     * @param string $jwt
     * @return object
     */
    public function decodeHeader(string $jwt): object
    {
        $tks = explode('.', $jwt);
        return JWT::jsonDecode(JWT::urlsafeB64Decode($tks[0]));
    }

    /**
     * Get the JSON Web Keys from the Cognito User Pool.
     * 
     * @return array
     */
    public function getJwk(string $kid): array
    {
        $region = config('cognito.aws_region');
        $userPoolId = config('cognito.user_pool_id');

        return cache()->remember("cognito.{$region}.{$userPoolId}.jwks.{$kid}", 60 * 60 * 24, function () use ($region, $userPoolId, $kid) {
            $jwk = json_decode(
                file_get_contents("https://cognito-idp.{$region}.amazonaws.com/{$userPoolId}/.well-known/jwks.json"),
                true
            );

            return collect($jwk['keys'] ?? [])->firstWhere('kid', $kid);
        });
    }

    /**
     * Although we already know the token has a valid signature and is
     * unexpired, this method is used to validate the payload.
     *
     * @param object $payload
     * @return void
     * @throws InvalidTokenException | Throwable
     */
    public function validatePayload(object $payload): void
    {
        if (!Uuid::isValid($payload->sub)) {
            throw new InvalidTokenException('Invalid token attributes. Parameters "sub" must be a UUID.');
        }
    }
}