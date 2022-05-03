
## 支持加密方式

| alg   | 实现方式      | key参数                       |
| ----- | ------------- | ----------------------------- |
| ES384 | openssl       | 数组包含publicKey和privateKey |
| ES256 | openssl       | 数组包含publicKey和privateKey |
| HS256 | hash_hmac     | 字符串                        |
| HS384 | hash_hmac     | 字符串                        |
| HS512 | hash_hmac     | 字符串                        |
| RS256 | openssl       | 数组包含publicKey和privateKey |
| RS384 | openssl       | 数组包含publicKey和privateKey |
| RS512 | openssl       | 数组包含publicKey和privateKey |
| EdDSA | sodium_crypto | 字符串                        |



## 异常捕捉
~~~
whereof\Signature\Exceptions\SignatureInvalidException 签名不正确
whereof\Signature\Exceptions\BeforeValidException 签名在某个时间点之后才能用
whereof\Signature\Exceptions\ExpiredException 签名失效
~~~


## Example

~~~
$time    = time();
$payload = [
    'iss'  => 'github.com',//签发人
    'iat'  => $time, //签发时间
    'nbf'  => $time, //生成签名之后生效
    'exp'  => $time + 7200, //过期时间
    'data' => [
        'id'       => 88,
        'username' => 'whereof'
    ],
];

$jwt = new \whereof\Signature\Crypt\Jwt(\whereof\Signature\Support\KeyHelper::key());
$token = $jwt->encode($payload);
$data = $jwt->decode($token);
~~~

## Example with RS256 (openssl)

~~~
$jwt = new \whereof\Signature\Crypt\Jwt( \whereof\Signature\Support\KeyHelper::RS256File(),'RS256');
$jwt = new \whereof\Signature\Crypt\Jwt( \whereof\Signature\Support\KeyHelper::RS256PemFile(),'RS256'));
$token = $jwt->encode($payload);
$data = $jwt->decode($token);
~~~

## Example with EdDSA (libsodium and Ed25519 signature)

~~~
$jwt = new \whereof\Signature\Crypt\Jwt( \whereof\Signature\Support\KeyHelper::randomEdDSA(),'EdDSA');
$token = $jwt->encode($payload);
$data = $jwt->decode($token);
~~~

