## 常量

~~~
\whereof\Signature\Sign::$leeway // 当前请求timestamp的生命周期内有效
~~~

## 异常捕捉

~~~
whereof\Signature\Exceptions\SignatureInvalidException 签名不正确
whereof\Signature\Exceptions\ExpiredException 签名失效
~~~

## 实例化

~~~
$sign = new \whereof\Signature\Crypt\Sign();
~~~

## 生成`appId`和`appSecret`

> 我们要告诉客户端2个值`appId`和`appSecret`，这2个值也要进行存储，服务端验证需要用到

~~~
//如果你传userid就按照userid去生成，没有就随机18位
$appid     = $sign->buildAppid($userId);
//随机32位
$appSecret = $sign->buildAppSecret();
~~~

## 客户端使用

~~~
// 客户端待发送的数据包
$data = array(
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
~~~

## 服务端进行验证

~~~
//根据请求过来的$data数据解析出appid，然后在根据appid查到appSecret
$sign->verifySign($appSecret, $data);
~~~



> Java md5 加密 org.apache.commons.codec.digest.DigestUtils.md5Hex($params . $appSecret)
