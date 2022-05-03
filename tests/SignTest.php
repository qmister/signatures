<?php


namespace whereof\Signature\Test;


use PHPUnit\Framework\TestCase;
use whereof\Signature\Crypt\Sign;

class SignTest extends TestCase
{
    public function testEq()
    {
        $appid     = 'djskaldjkasj';
        $appSecret = 'dasjdkalsjdkasjdkla';
        $data      = array(
            'sex'       => '1',
            'age'       => '16',
            'addr'      => 'whereof',
            'appid'     => $appid,//必传
            'timestamp' => time(),//必传
        );
        function sign($appSecret, array $input = [])
        {
            // 对数组的值按key排序
            ksort($input);
            // 生成url的形式
            $params = http_build_query($input);
            // 生成sign
            $sign = md5($params . $appSecret);
            return $sign;
        }

        $data['sign'] = sign($appSecret, $data);
        $sign         = new Sign();
        $foo          = $sign->verifySign($appSecret, $data);
        $this->assertIsBool(true, $foo);
    }

    public function testSign()
    {
        $appid        = 'djskaldjkasj';
        $appSecret    = 'dasjdkalsjdkasjdkla';
        $data         = array(
            'sex'       => '1',
            'age'       => '16',
            'addr'      => 'whereof',
            'appid'     => $appid,//必传
            'timestamp' => time(),//必传
        );
        $sign         = new Sign();
        $data['sign'] = $sign->sign($appSecret, $data);

        $foo = $sign->verifySign($appSecret, $data);
        $this->assertIsBool(true, $foo);
    }
}