<?php


namespace whereof\Signature\Test;


use PHPUnit\Framework\TestCase;
use whereof\Signature\Crypt\Discuz;
use whereof\Signature\Support\KeyHelper;

class DiscuzTest extends TestCase
{
    public function testEq()
    {
        $payload = [
            'iss'  => 'github.com',//签发人
            'data' => [
                'id'       => 88,
                'username' => 'whereof'
            ],
        ];

        $auto  = new Discuz(KeyHelper::key());
        $token = $auto->encode($payload);
        $data  = $auto->decode($token);
        $d     = json_decode($data, true);
        $this->assertEquals($d['iss'], 'github.com');
        $this->assertEquals($d['data']['id'], '88');
        $this->assertEquals($d['data']['username'], 'whereof');
    }

}