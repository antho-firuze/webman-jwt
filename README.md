# JSON Web Token (JWT) for webman plugin

[![License](http://poser.pugx.org/tinywan/jwt/license)](https://packagist.org/packages/tinywan/jwt)
[![Latest Stable Version](http://poser.pugx.org/tinywan/jwt/v)](https://packagist.org/packages/tinywan/jwt)
[![Total Downloads](http://poser.pugx.org/tinywan/jwt/downloads)](https://packagist.org/packages/tinywan/jwt)
[![Monthly Downloads](http://poser.pugx.org/tinywan/jwt/d/monthly)](https://packagist.org/packages/tinywan/jwt)
[![Daily Downloads](http://poser.pugx.org/tinywan/jwt/d/daily)](https://packagist.org/packages/tinywan/jwt)
[![PHP Version Require](http://poser.pugx.org/tinywan/jwt/require/php)](https://packagist.org/packages/tinywan/jwt)

Json web token (JWT), A kind of based on the transmission of a statement between the network application environment JSON Open standard (RFC 7519)，Should token It is designed to be compact and secure, especially suitable for single -point login (SSO) scenarios of distributed sites.

JWT The statement is generally used to pass the certified user identity information between identity providers and service providers, in order to obtain resources from resource servers, and can also increase the declaration information necessary for other business logic. token It can also be directly used for certification or encryption.

## Certification & Authorization Process

![image](https://user-images.githubusercontent.com/14959876/159104533-f51f0a57-e085-44ab-84d7-363a4bb1eda9.png)

## Signature process

1. The user uses the username and password to the request certification on the certification server.
2. After the authentication server verifies the user name and password, generate JWT Token，this token The generation process is as follows:
   - The authentication server will also generate a Secret Key (key)
   - Seek Base64 for JWT Header and JWT Payload, respectively.Payload may include the user's abstract ID and the expiration time.
   - Sign the key to JWT `HMAC-SHA256(SecretKey, Base64UrlEncode(JWT-Header)+'.'+Base64UrlEncode(JWT-Payload))`
3. Then `base64(header).base64(payload).signature` Back to the client as JWT Token.
4. The client uses JWT Token to send related requests to the application server.This JWT Token is like a temporary user certificate.

## Install

```shell
composer require firuze/jwt
```

## use

### Token

```php
use Firuze\Jwt\JwtToken;

$user = [
    'id'  => 2022,
    'name'  => 'Firuze',
    'email' => 'Firuze@163.com'
];
$token = JwtToken::generateToken($user);
var_dump(json_encode($token));
```

**Output (json format)**

```json
{
  "token_type": "Bearer",
  "expires_in": 36000,
  "access_token": "eyJ0eXAiOiJAUR-Gqtnk9LUPO8IDrLK7tjCwQZ7CI...",
  "refresh_token": "eyJ0eXAiOiJIEGkKprvcccccQvsTJaOyNy8yweZc..."
}
```

**Response parameter**

| parameter          | type   | describe                          | Exemplary               |
| :------------ | :----- | :---------------------------- | :------------------- |
| token_type    | string | Token type                    | Bearer               |
| expires_in    | int    | Valley valid time, unit: second        | 36000                |
| access_token  | string | Access voucher                      | XXXXXXXXXXXXXXXXXXXX |
| refresh_token | string | Refresh the voucher (the access voucher is expired and used ） | XXXXXXXXXXXXXXXXXXXX |

## List of supporting functions

1. Get the current`id`

```php
$id = Firuze\Jwt\JwtToken::getCurrentId();
```

2. Get all fields

```php
$email = Firuze\Jwt\JwtToken::getExtend();
```

3. Get the custom field

```php
$email = Firuze\Jwt\JwtToken::getExtendVal('email');
```

4. Refresh the token (to get the access token by getting a new token)

```php
$refreshToken = Firuze\Jwt\JwtToken::refreshToken();
```

5. The remaining time of the tokens is valid

```php
$exp = Firuze\Jwt\JwtToken::getTokenExp();
```

6. Login single device.The default is closed, please modify the configuration file `config/plugin/firuze/jwt`
```php
'is_single_device' => true,
```

> Single device login supports definition client `client` field, custom client single-point login (defaults to `WEB`, web page), such as:`MOBILE`、`APP`、`WECHAT`、`WEB`、`ADMIN`、`API`、`OTHER` etc.

```php
$user = [
    'id'  => 2022,
    'name'  => 'Firuze',
    'client' => 'MOBILE',
];
$token = Firuze\Jwt\JwtToken::generateToken($user);
var_dump(json_encode($token));
```

7. Get the current user information (model)

```php
$user = Firuze\Jwt\JwtToken::getUser();
```

This configuration item `'User_model'` is an anonymous function, returns the air array by default, and can customize its own return model according to its own ORM

**ThinkORM** Configuration

```php
'user_model' => function($uid) {
// Return a array
return \think\facade\Db::table('resty_user')
	->field('id,username,create_time')
	->where('id',$uid)
	->find();
}
```

**LaravelORM** Configuration

```php
'user_model' => function($uid) {
// Return a object
return \support\Db::table('resty_user')
	->where('id', $uid)
	->select('id','email','mobile','create_time')
	->first();
}
```

8. Token cleaning

```php
$res = Firuze\Jwt\JwtToken::clear();
```

> Only configuration items `is_single_device` for `true` Only will it take effect. Optional parameter: `MOBILE`、`APP`、`WECHAT`、`WEB`、`ADMIN`、`API`、`OTHER` etc.

9. Custom terminal `Client`

```php
// Generate web token
$user = [
    'id'  => 2022,
    'name'  => 'Firuze',
    'client' => JwtToken::TOKEN_CLIENT_WEB
];
$token = JwtToken::generateToken($user);

// Generate mobile token
$user = [
    'id'  => 2022,
    'name'  => 'Firuze',
    'client' => JwtToken::TOKEN_CLIENT_MOBILE
];
$token = JwtToken::generateToken($user);
```

The default is the `WEB` end

10. Custom access to token and refresh token expires

```php
$extend = [
    'id'  => 2024,
    'access_exp'  => 7200,  // 2 Hour
];
$token = Firuze\Jwt\JwtToken::generateToken($extend);
```

## Signature algorithm

JWT The most common signature algorithms (JWA)：`HS256(HMAC-SHA256)` 、`RS256(RSA-SHA256)` besides `ES256(ECDSA-SHA256)`

### JWT The algorithm list is as follows

```php
+--------------+-------------------------------+--------------------+
| "alg" Param  | Digital Signature or MAC      | Implementation     |
| Value        | Algorithm                     | Requirements       |
+--------------+-------------------------------+--------------------+
| HS256        | HMAC using SHA-256            | Required           |
| HS384        | HMAC using SHA-384            | Optional           |
| HS512        | HMAC using SHA-512            | Optional           |
| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
|              | SHA-256                       |                    |
| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-384                       |                    |
| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-512                       |                    |
| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
| PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
|              | MGF1 with SHA-256             |                    |
| PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
|              | MGF1 with SHA-384             |                    |
| PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
|              | MGF1 with SHA-512             |                    |
| none         | No digital signature or MAC   | Optional           |
|              | performed                     |                    |
+--------------+-------------------------------+--------------------+

The use of "+" in the Implementation Requirements column indicates
that the requirement strength is likely to be increased in a future
version of the specification.
```

> You can see that only RS256 and ES256 are marked as RECOMMENDED.

### Symmetrical encryption algorithm

> The plug -in installation uses the `HS256` symmetrical encryption algorithm.

HS256 uses the same one `「secret_key」` Signature and verification. once `secret_key` There is no security at all. Therefore HS256 It is only suitable for centralized certification, and the signature and verification must be performed by the trusted party.

### Asymmetric plus algorithm

> The RS256 series uses the RSA private key for signature and uses the RSA public key for verification.

Even if the public key has no effect, it has no effect, as long as the private key is safe.RS256 can entrust verification to other applications, as long as the public key is given.

> The following is a command of the RS series algorithm, for reference only

### RS512

```php
ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P "" -f RS512.key
openssl rsa -in RS512.key -pubout -outform PEM -out RS512.key.pub
```

### RS512

```php
ssh-keygen -t rsa -b 4096 -E SHA354 -m PEM -P "" -f RS384.key
openssl rsa -in RS384.key -pubout -outform PEM -out RS384.key.pub
```

### RS256

```php
ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P "" -f RS256.key
openssl rsa -in RS256.key -pubout -outform PEM -out RS256.key.pub
```

## 🚀 Video address

> Students who do n’t understand can understand the video, there will be detailed explanations

- How to use JWT authentication plug-in: https://www.bilibili.com/video/BV1HS4y1F7Jx
- How to use the JWT authentication plug-in (algorithm): https://www.bilibili.com/video/BV14L4y1g7sY

## safety

https://www.w3cschool.cn/fastapi/fastapi-cmia3lcw.html

### concept

There are many ways to deal with problems such as security, identity authentication and authorization.And this is usually a complex and "difficult" topic.In many frameworks and systems, it will cost a lot of energy and code to deal with security and identity certification (in many cases, it may account for 50 % or more of all code written codes).

JWT can help you handle safety easily and quickly without studying and learning all safety specifications.

### Scenes

Suppose you have a back -end API in a certain domain.And you have a front end in different paths (or mobile applications) in another domain or the same domain.And you hope that there is a way for the front end to use the username and password and the back end for identity verification.We can use OAUTH2 to build it through JWT.

### Authentication process

- The user enters the `username` and `password` at the front end, and then click Enter.
- The front end (runs in the user's browser) Send a `username` and `password` Our API in a specific URL (to declare `tokenUrl="token"`）。
- API check Username and Password, and responds with "token" (we haven't realized any of these). "Token" is just a string containing some content. We can use it later to verify this user.Generally, the tokens are set to expire after a period of time.Therefore, users will have to log in again later. If the tokens are stolen, the risk is small. It is not like a permanent and effective key (in most cases).
  The front end is temporarily stored somewhere.
- Users click the front end to transfer to another part of the front-end web application.
- The front end needs to get more data from the API. But it needs to verify the specific endpoint. Therefore, in order to use us API For authentication, it will send `Authorization`A value`Bearer` add token head. If token contains `foobar`，but `Authorization` The content of the header will be: `Bearer foobar`。`Note: There is a space in the middle`。
