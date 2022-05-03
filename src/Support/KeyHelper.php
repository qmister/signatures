<?php


namespace whereof\Signature\Support;


/**
 * Class KeyHelper
 * @package whereof\Signature\Support
 */
class KeyHelper
{

    /**
     * @param null $key
     * @return string|null
     */
    public static function key($key = null)
    {
        return $key ?? md5('whereof-jwt-token');
    }

    /**
     *
     * @param array $config
     * @param null $passphrase
     * @return array
     */
    public function randomPkey($config = [], $passphrase = null)
    {
        $new_key = openssl_pkey_new($config);
        openssl_pkey_export($new_key, $private_key, $passphrase, $config);
        $public_key = openssl_pkey_get_details($new_key);
        return [
            'publicKey'  => $public_key['key'],
            'privateKey' => $private_key,
        ];
    }

    /**
     * @return array
     */
    public static function randomEdDSA()
    {
        $keyPair = sodium_crypto_sign_keypair();
        return [
            'publicKey'  => base64_encode(sodium_crypto_sign_publickey($keyPair)),
            'privateKey' => base64_encode(sodium_crypto_sign_secretkey($keyPair)),
        ];
    }


    /**
     * @param string $publicFile
     * @param string $privateKeyFile
     * @return array
     */
    public static function RS256File($publicFile = "", $privateKeyFile = "")
    {
        $publicFile     = is_file($publicFile) ? $publicFile : __DIR__ . '/../Keys/rs256.pub';
        $privateKeyFile = is_file($privateKeyFile) ? $privateKeyFile : __DIR__ . '/../Keys/rs256';
        return [
            'publicKey'  => file_get_contents($publicFile),
            'privateKey' => file_get_contents($privateKeyFile),
        ];
    }

    /**
     * @param  $pemFile
     * @param  $passphrase
     * @return array
     */
    public static function RS256PemFile($pemFile = "", $passphrase = "")
    {
        $pemFile    = is_file($pemFile) ? $pemFile : __DIR__ . '/../Keys/rs256.pem';
        $privateKey = openssl_pkey_get_private(
            file_get_contents($pemFile),
            $passphrase
        );
        return [
            'publicKey'  => openssl_pkey_get_details($privateKey)['key'],
            'privateKey' => $privateKey,
        ];
    }
}