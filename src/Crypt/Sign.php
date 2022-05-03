<?php
/*
 * Desc: 
 * User: zhiqiang
 * Date: 2021-10-09 00:06
 */

namespace whereof\Signature\Crypt;

use UnexpectedValueException;
use whereof\Signature\Exceptions\ExpiredException;
use whereof\Signature\Exceptions\SignatureInvalidException;

/**
 * appId 生成规则18位
 * appSecret 生成规则32位
 *
 * Class Sign
 * @package whereof\Signature
 */
class Sign
{
    /**
     * 10分钟失效
     * @var int
     */
    public static $leeway = 600;

    /**
     * 生成签名
     * @param $appSecret
     * @param array $input
     * @return string
     */
    public function sign($appSecret, array $input = [])
    {
        // 对数组的值按key排序
        ksort($input);
        // 生成url的形式
        $params = http_build_query($input);
        // 生成sign
        $sign = md5($params . $appSecret);
        return $sign;
    }

    /**
     * 验证签名
     * @param $appSecret
     * @param array $input
     * @return bool
     */
    public function verifySign($appSecret, $input = [])
    {
        if (empty($input['sign'])) {
            throw new UnexpectedValueException('sign Undefined');
        }
        if (empty($input['timestamp'])) {
            throw new UnexpectedValueException('timestamp Undefined');
        }
        if (time() - $input['timestamp'] > static::$leeway) {
            throw new ExpiredException('timestamp Expired');
        }
        $sign = (string)$input['sign'];
        unset($input['sign']);
        ksort($input);
        $params = http_build_query($input);
        $sign2 = md5($params . $appSecret);
        if ($sign != $sign2) {
            throw new SignatureInvalidException('Signature verification failed');
        }
        return true;
    }
}