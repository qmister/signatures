> Auto是Discuz!开发的使用异或运算进行加密和解密，

## Example

~~~
$time    = time();
$payload = [
    'iss'  => 'github.com',//签发人
    'data' => [
        'id'       => 88,
        'username' => 'whereof'
    ],
];

$auto = new \whereof\Signature\Crypt\Discuz(\whereof\Signature\Support\KeyHelper::key());
$token = $auto->encode($payload);
$data = $auto->decode($token);
~~~