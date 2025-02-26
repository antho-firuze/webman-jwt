<?php

/**
 * @desc JwtToken.php 描述信息
 * @author Tinywan(ShaoBo Wan)
 * @modified Firuze(Antho Firuze)
 * @date 2024/04/24
 */

declare(strict_types=1);

namespace Firuze\Jwt;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Firuze\Jwt\Exception\JwtCacheTokenException;
use Firuze\Jwt\Exception\JwtRefreshTokenExpiredException;
use Firuze\Jwt\Exception\JwtTokenException;
use Firuze\Jwt\Exception\JwtConfigException;
use Firuze\Jwt\Exception\JwtTokenExpiredException;
use UnexpectedValueException;

class JwtToken
{
    /**
     * access_token.
     */
    private const ACCESS_TOKEN = 1;

    /**
     * refresh_token.
     */
    private const REFRESH_TOKEN = 2;

    /** WEB Client. */
    public const TOKEN_CLIENT_WEB = 'WEB';

    /** Mobile Client. */
    public const TOKEN_CLIENT_MOBILE = 'MOBILE';

    /**
     * @desc: Get the current login ID
     * @return mixed
     * @throws JwtTokenException
     * @author Tinywan(ShaoBo Wan)
     */
    public static function getCurrentId()
    {
        return self::getExtendVal('id') ?? 0;
    }

    /**
     * @desc: Get the current user information
     * @return mixed
     * @author Tinywan(ShaoBo Wan)
     */
    public static function getUser()
    {
        $config = self::_getConfig();
        if (is_callable($config['user_model'])) {
            return $config['user_model'](self::getCurrentId());
        }
        return [];
    }

    /**
     * @desc: Get the value of the specified token extension content field
     *
     * @param string $val
     * @return mixed|string
     * @throws JwtTokenException
     */
    public static function getExtendVal(string $val)
    {
        return self::getTokenExtend()[$val] ?? '';
    }

    /**
     * @desc Get the specified token extension content
     * @return array
     * @throws JwtTokenException
     */
    public static function getExtend(): array
    {
        return self::getTokenExtend();
    }

    /**
     * @desc: Refresh token
     *
     * @return array|string[]
     * @throws JwtTokenException
     */
    public static function refreshToken(): array
    {
        $token = self::getTokenFromHeaders();
        $config = self::_getConfig();
        try {
            $extend = self::verifyToken($token, self::REFRESH_TOKEN);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtRefreshTokenExpiredException('Refresh token invalid');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtRefreshTokenExpiredException('Refresh the token cards have not taken effect yet');
        } catch (ExpiredException $expiredException) {
            throw new JwtRefreshTokenExpiredException('Refresh the token session has expired, please log in again!');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtRefreshTokenExpiredException('Refresh the expansion field obtained by the token does not exist');
        } catch (JwtCacheTokenException | \Exception $exception) {
            throw new JwtRefreshTokenExpiredException($exception->getMessage());
        }
        $payload = self::generatePayload($config, $extend['extend']);
        $secretKey = self::getPrivateKey($config);
        $extend['exp'] = time() + $config['access_exp'];
        $newToken['access_token'] = self::makeToken($extend, $secretKey, $config['algorithms']);
        if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
            $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
            $payload['exp'] = time() + $config['refresh_exp'];
            $newToken['refresh_token'] = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        }
        if ($config['is_single_device']) {
            $client = $extend['extend']['client'] ?? self::TOKEN_CLIENT_WEB;
            RedisHandler::generateToken($config['cache_token_pre'], (string)$client, (string)$extend['extend']['id'], $config['access_exp'], $newToken['access_token']);
            RedisHandler::refreshToken($config["cache_refresh_token_pre"], (string)$client, (string)$extend['extend']['id'], $config['refresh_exp'], $newToken['refresh_token']);
        }
        return $newToken;
    }

    /**
     * @desc: Token.
     * @param array $extend
     * @return array
     * @throws JwtConfigException
     */
    public static function generateToken(array $extend): array
    {
        if (!isset($extend['id'])) {
            throw new JwtTokenException('Lack of global unique field: ID');
        }
        $config = self::_getConfig();
        $config['access_exp'] = $extend['access_exp'] ?? $config['access_exp'];
        $config['refresh_exp'] = $extend['refresh_exp'] ?? $config['refresh_exp'];
        $payload = self::generatePayload($config, $extend);
        $secretKey = self::getPrivateKey($config);
        $token = [
            'token_type' => 'Bearer',
            'expires_in' => $config['access_exp'],
            'access_token' => self::makeToken($payload['accessPayload'], $secretKey, $config['algorithms'])
        ];
        if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
            $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
            $token['refresh_token'] = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        }
        if ($config['is_single_device']) {
            $client = $extend['client'] ?? self::TOKEN_CLIENT_WEB;
            RedisHandler::generateToken($config['cache_token_pre'], (string)$client, (string)$extend['id'], $config['access_exp'], $token['access_token']);
            if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
                if (isset($config["cache_refresh_token_pre"])) {
                    RedisHandler::generateToken($config["cache_refresh_token_pre"], (string)$client, (string)$extend['id'], $config['refresh_exp'], $token['refresh_token']);
                }
            }
        }
        return $token;
    }

    /**
     * @desc: Verification token
     * @param int $tokenType
     * @param string|null $token
     * @return array
     * @throws JwtTokenException
     * @author Tinywan(ShaoBo Wan)
     */
    public static function verify(int $tokenType = self::ACCESS_TOKEN, ?string $token = null): array
    {
        $token = $token ?? self::getTokenFromHeaders();
        try {
            return self::verifyToken($token, $tokenType);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtTokenException('Identity verification token invalid');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtTokenException('Identity verification tokens have not taken effect');
        } catch (ExpiredException $expiredException) {
            throw new JwtTokenExpiredException('Identity verification session has expired, please log in again!');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('The expansion field obtained does not exist');
        } catch (JwtCacheTokenException | \Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }
    }

    /**
     * @desc: Get the expansion field.
     * @return array
     * @throws JwtTokenException
     */
    private static function getTokenExtend(): array
    {
        return (array)self::verify()['extend'];
    }

    /**
     * @desc: The remaining time of the tokens is valid.
     * @param int $tokenType
     * @return int
     */
    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN): int
    {
        return (int)self::verify($tokenType)['exp'] - time();
    }

    /**
     * @desc: Get the header head Authorization token
     *
     * @throws JwtTokenException
     */
    private static function getTokenFromHeaders(): string
    {
        $authorization = request()->header('authorization');
        if (!$authorization || 'undefined' == $authorization) {
            $config = self::_getConfig();
            if (!isset($config['is_support_get_token']) || false === $config['is_support_get_token']) {
                throw new JwtTokenException('Request the information that is not carried by Authorization');
            }
            $authorization = request()->get($config['is_support_get_token_key']);
            if (empty($authorization)) {
                throw new JwtTokenException('Request the information that is not carried by Authorization');
            }
            $authorization = 'Bearer ' . $authorization;
        }

        if (self::REFRESH_TOKEN != substr_count($authorization, '.')) {
            throw new JwtTokenException('Illegal authorization information');
        }

        if (2 != count(explode(' ', $authorization))) {
            throw new JwtTokenException('The voucher format in the Bearer verification is wrong, and there must be a space in the middle');
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            throw new JwtTokenException('The interface authentication method needs to be bearer');
        }
        if (!$token || 'undefined' === $token) {
            throw new JwtTokenException('Authorization information that tries to obtain does not exist');
        }

        return $token;
    }

    /**
     * @desc: Verification token
     * @param string $token
     * @param int $tokenType
     * @return array
     * @author Tinywan(ShaoBo Wan)
     */
    private static function verifyToken(string $token, int $tokenType): array
    {
        $config = self::_getConfig();
        $publicKey = self::ACCESS_TOKEN == $tokenType ? self::getPublicKey($config['algorithms']) : self::getPublicKey($config['algorithms'], self::REFRESH_TOKEN);
        JWT::$leeway = $config['leeway'];

        $decoded = JWT::decode($token, new Key($publicKey, $config['algorithms']));
        $decodeToken = json_decode(json_encode($decoded), true);
        if ($config['is_single_device']) {
            $cacheTokenPre = $config['cache_token_pre'];
            if ($tokenType == self::REFRESH_TOKEN) {
                $cacheTokenPre = $config['cache_refresh_token_pre'];
            }
            $client = $decodeToken['extend']['client'] ?? self::TOKEN_CLIENT_WEB;
            RedisHandler::verifyToken($cacheTokenPre, $client, (string)$decodeToken['extend']['id'], $token);
        }
        return $decodeToken;
    }

    /**
     * @desc: Token.
     *
     * @param array $payload Load information
     * @param string $secretKey Signature key
     * @param string $algorithms algorithm
     * @return string
     */
    private static function makeToken(array $payload, string $secretKey, string $algorithms): string
    {
        return JWT::encode($payload, $secretKey, $algorithms);
    }

    /**
     * @desc: Get the dense carrier.
     *
     * @param array $config Configuration file
     * @param array $extend Extended encryption field
     * @return array
     */
    private static function generatePayload(array $config, array $extend): array
    {
        $basePayload = [
            'iss' => $config['iss'], // Issuer
            'aud' => $config['iss'], // Receive the party of the JWT
            'iat' => time(), // Issue time
            'nbf' => time() + ($config['nbf'] ?? 0), // It can only be accessed at a certain point in time
            'exp' => time() + $config['access_exp'], // Expiration
            'extend' => $extend // Custom extension information
        ];
        $resPayLoad['accessPayload'] = $basePayload;
        $basePayload['exp'] = time() + $config['refresh_exp'];
        $resPayLoad['refreshPayload'] = $basePayload;

        return $resPayLoad;
    }

    /**
     * @desc: Get the [Public Key] signature value according to the signature algorithm
     * @param string $algorithm algorithm
     * @param int $tokenType type
     * @return string
     * @throws JwtConfigException
     */
    private static function getPublicKey(string $algorithm, int $tokenType = self::ACCESS_TOKEN): string
    {
        $config = self::_getConfig();
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_public_key'] : $config['refresh_public_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * @desc: Get the [Private Key] signature value according to the signature algorithm
     * @param array $config Configuration file
     * @param int $tokenType Token
     * @return string
     */
    private static function getPrivateKey(array $config, int $tokenType = self::ACCESS_TOKEN): string
    {
        switch ($config['algorithms']) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_private_key'] : $config['refresh_private_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * @desc: Get the configuration file
     * @return array
     * @throws JwtConfigException
     */
    private static function _getConfig(): array
    {
        $config = config('plugin.firuze.jwt.app.jwt');
        if (empty($config)) {
            throw new JwtConfigException('JWT configuration file does not exist');
        }
        return $config;
    }

    /**
     * @desc: Logged out token
     * @param string $client
     * @return bool
     */
    public static function clear(string $client = self::TOKEN_CLIENT_WEB): bool
    {
        $config = self::_getConfig();
        if ($config['is_single_device']) {
            $clearCacheRefreshTokenPre = RedisHandler::clearToken($config['cache_refresh_token_pre'], $client, (string)self::getCurrentId());
            $clearCacheTokenPre = RedisHandler::clearToken($config['cache_token_pre'], $client, (string)self::getCurrentId());
            return $clearCacheTokenPre && $clearCacheRefreshTokenPre;
        }
        return true;
    }
}
