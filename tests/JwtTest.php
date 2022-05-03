<?php


namespace whereof\Signature\Test;


use PHPUnit\Framework\TestCase;
use whereof\Signature\Crypt\Jwt;
use whereof\Signature\Support\KeyHelper;

/**
 * Class JwtTest
 * @package whereof\Signature\Test
 */
class JwtTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testJwt()
    {
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
        $jwt     = new Jwt(KeyHelper::key());
        $token   = $jwt->encode($payload);
        $data    = $jwt->decode($token);
        $foo     = json_encode($payload) == json_encode($data, true);
        $this->assertTrue($foo);
    }

    /**
     * @throws \Exception
     */
    public function testJwtRS256()
    {
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
        $jwt     = new Jwt(KeyHelper::RS256PemFile(), 'RS256');
        $token   = $jwt->encode($payload);
        $data    = $jwt->decode($token);
        $foo     = json_encode($payload) == json_encode($data, true);
        $this->assertTrue($foo);
    }

    /**
     * @throws \Exception
     */
    public function testJwtRS256File()
    {
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
        $jwt     = new Jwt(KeyHelper::RS256File(), 'RS256');
        $token   = $jwt->encode($payload);
        $data    = $jwt->decode($token);
        $foo     = json_encode($payload) == json_encode($data, true);
        $this->assertTrue($foo);
    }

    /**
     * @throws \Exception
     */
    public function testJwtEd25519()
    {
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
        $jwt     = new Jwt(KeyHelper::randomEdDSA(), 'EdDSA');
        $token   = $jwt->encode($payload);
        $data    = $jwt->decode($token);
        $foo     = json_encode($payload) == json_encode($data, true);
        $this->assertTrue($foo);
    }
}