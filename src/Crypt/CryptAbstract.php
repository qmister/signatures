<?php
/*
 * Desc: 
 * User: zhiqiang
 * Date: 2021-10-08 23:57
 */

namespace whereof\Signature\Crypt;

/**
 * Class CryptAbstract
 * @author zhiqiang
 * @package whereof\Signature\Crypt
 */
abstract class CryptAbstract
{

    protected $key;

    public function __construct($key)
    {
        $this->key = $key;
    }

    /**
     * @param $data
     * @return mixed
     */
    abstract public function encode($data);


    /**
     * @param $str
     * @return mixed
     */
    abstract public function decode($str);
}