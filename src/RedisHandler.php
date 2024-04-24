<?php

/**
 * @desc RedisHanle.php Description
 * @author Tinywan(ShaoBo Wan)
 * @modified Firuze(Antho Firuze)
 * @date 2024/04/24
 */

declare(strict_types=1);

namespace Firuze\Jwt;

use support\Redis;
use Firuze\Jwt\Exception\JwtCacheTokenException;

class RedisHandler
{
    /**
     * @desc: Generate cache decent
     * (1) When logging in, determine whether the account is logged in at other devices. If so, please be eliminated before the empty.
     * (2) Re -set the key, and then store user information in Redis
     * @param string $pre
     * @param string $client
     * @param string $uid
     * @param int $ttl
     * @param string $token
     * @author Tinywan(ShaoBo Wan)
     */
    public static function generateToken(string $pre, string $client, string $uid, int $ttl, string $token): void
    {
        $cacheKey = $pre . $client . ':' . $uid;
        Redis::del($cacheKey);
        Redis::setex($cacheKey, $ttl, $token);
    }


    /**
     * @desc: Refresh the stored cache token
     * @param string $pre
     * @param string $client
     * @param string $uid
     * @param int $ttl
     * @param string $token
     * @return void
     */
    public static function refreshToken(string $pre, string $client, string $uid, int $ttl, string $token): void
    {
        $cacheKey = $pre . $client . ':' . $uid;
        $isExists = Redis::exists($cacheKey);
        if ($isExists) {
            $ttl = Redis::ttl($cacheKey);
        }
        Redis::setex($cacheKey, $ttl, $token);
    }

    /**
     * @desc: Check the device cache token
     * @param string $pre
     * @param string $client
     * @param string $uid
     * @param string $token
     * @return bool
     * @author Tinywan(ShaoBo Wan)
     */
    public static function verifyToken(string $pre, string $client, string $uid, string $token): bool
    {
        $cacheKey = $pre . $client . ':' . $uid;
        if (!Redis::exists($cacheKey)) {
            throw new JwtCacheTokenException('This account has been logged in on other devices and forced offline');
        }
        if (Redis::get($cacheKey) != $token) {
            throw new JwtCacheTokenException('Identity verification session has expired, please log in again!');
        }
        return true;
    }

    /**
     * @desc: Cleaning the cache decent
     * @param string $pre
     * @param string $client
     * @param string $uid
     * @return bool
     * @author Tinywan(ShaoBo Wan)
     */
    public static function clearToken(string $pre, string $client, string $uid): bool
    {
        Redis::del($pre . $client . ':' . $uid);
        return true;
    }
}
