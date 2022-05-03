<?php
/*
 * Desc: 
 * User: zhiqiang
 * Date: 2021-10-09 00:07
 */

namespace whereof\Signature\Crypt;

use DateTime;
use DomainException;
use Exception;
use UnexpectedValueException;
use whereof\Helper\ArrayHelper;
use whereof\Helper\JsonHelper;
use whereof\Helper\StrHelper;
use whereof\Signature\Exceptions\BeforeValidException;
use whereof\Signature\Exceptions\ExpiredException;
use whereof\Signature\Exceptions\SignatureInvalidException;

/**
 * Class Jwt
 * @author zhiqiang
 * @package whereof\Signature\Crypt
 */
class Jwt extends CryptAbstract
{

    const ASN1_INTEGER    = 0x02;
    const ASN1_SEQUENCE   = 0x10;
    const ASN1_BIT_STRING = 0x03;

    /**
     * @var string
     */
    protected $key;
    /**
     * @var string
     */
    protected $alg;

    /**
     * @var int
     */
    public $leeway = 0;

    /**
     * @var int
     */
    public $timestamp;

    /**
     * @var array
     */
    protected static $supported_algs = array(
        'ES384' => array('openssl', 'SHA384'),
        'ES256' => array('openssl', 'SHA256'),
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
        'EdDSA' => array('sodium_crypto', 'EdDSA'),
    );

    /**
     * Jwt constructor.
     * @param $key
     * @param string $alg
     * @param int $leeway
     * @param null $timestamp
     * @throws Exception
     */
    public function __construct($key, $alg = 'HS256', $leeway = 0, $timestamp = null)
    {
        parent::__construct($key);
        if (!in_array($alg, array_keys(static::$supported_algs))) {
            throw new UnexpectedValueException('Algorithm not supported');
        }
        $this->alg       = $alg;
        $this->leeway    = $leeway;
        $this->timestamp = $timestamp ?? time();
        if (static::isOpenSsl()) {
            if (!ArrayHelper::keyExists('publicKey', $this->key)) {
                throw new UnexpectedValueException('key is Not set publicKey');
            }
            if (!ArrayHelper::keyExists('privateKey', $this->key)) {
                throw new UnexpectedValueException('key is Not set privateKey');
            }
        }
    }

    /**
     * @param $data
     * @return string
     * @throws Exception
     */
    public function encode($data)
    {
        if (static::isOpenSsl()) {
            $key = ArrayHelper::getValue($this->key, 'privateKey');
        } else {
            $key = $this->key;
        }
        $header        = array('typ' => 'JWT', 'alg' => $this->alg);
        $segments[]    = static::urlsafeB64Encode(JsonHelper::jsonEncode($header));
        $segments[]    = static::urlsafeB64Encode(JsonHelper::jsonEncode($data));
        $signing_input = \implode('.', $segments);
        $signature     = static::build($signing_input, $key, $this->alg);
        $segments[]    = static::urlsafeB64Encode($signature);
        return \implode('.', $segments);
    }

    /**
     * @param $str
     * @return mixed
     * @throws Exception
     */
    public function decode($str)
    {
        $tks = \explode('.', $str);
        if (count($tks) != 3) {
            throw new \UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = JsonHelper::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new \UnexpectedValueException('Invalid header encoding');
        }
        if (null === $payload = JsonHelper::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new \UnexpectedValueException('Invalid claims encoding');
        }
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new \UnexpectedValueException('Invalid signature encoding');
        }
        if (empty($header->alg)) {
            throw new \UnexpectedValueException('Empty algorithm');
        }
        if ($header->alg === 'ES256' || $header->alg === 'ES384') {
            // OpenSSL expects an ASN.1 DER sequence for ES256/ES384 signatures
            $sig = static::signatureToDER($sig);
        }

        if (static::isOpenSsl()) {
            $key = ArrayHelper::getValue($this->key, 'publicKey');
        } else {
            $key = $this->key;
        }

        if (\is_array($key) || $key instanceof \ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new \UnexpectedValueException('"kid" invalid, unable to lookup correct key');
                }
                $key = $key[$header->kid];
            } else {
                throw new \UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }
        }
        // Check the signature
        if (!static::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (isset($payload->nbf) && $payload->nbf > ($this->timestamp + $this->leeway)) {
            throw new BeforeValidException('Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->nbf));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (isset($payload->iat) && $payload->iat > ($this->timestamp + $this->leeway)) {
            throw new BeforeValidException('Cannot handle token prior to ' . \date(DateTime::ISO8601, $payload->iat));
        }

        if (isset($payload->exp) && ($this->timestamp - $this->leeway) >= $payload->exp) {
            throw new ExpiredException('Expired token');
        }
        return $payload;
    }


    /**
     * @return bool
     */
    protected function isOpenSsl()
    {
        static $openssl = [];
        foreach (static::$supported_algs as $algs => $v) {
            if ($v[0] == 'openssl' || $algs == 'EdDSA') {
                $openssl[] = $algs;
            }
        }
        return in_array($this->alg, $openssl);
    }

    /**
     * @param $msg
     * @param $key
     * @param string $alg
     * @return string
     */
    protected function build($msg, $key, $alg = 'HS256')
    {

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'hash_hmac':
                return \hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success   = \openssl_sign($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to sign data");
                }
                if ($alg === 'ES256') {
                    $signature = static::signatureFromDER($signature, 256);
                } elseif ($alg === 'ES384') {
                    $signature = static::signatureFromDER($signature, 384);
                }
                return $signature;
            case 'sodium_crypto':
                if (!function_exists('sodium_crypto_sign_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                try {
                    // The last non-empty line is used as the key.
                    $lines = array_filter(explode("\n", $key));
                    $key   = base64_decode(end($lines));
                    return \sodium_crypto_sign_detached($msg, $key);
                } catch (Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }
        }
        throw new UnexpectedValueException('Algorithm not supported');
    }

    /**
     * @param $der
     * @param $keySize
     * @return string
     */
    protected function signatureFromDER($der, $keySize)
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        list($offset, $_) = static::readDER($der);
        list($offset, $r) = static::readDER($der, $offset);
        list($offset, $s) = static::readDER($der, $offset);
        // Convert r-value and s-value from signed two's compliment to unsigned
        // big-endian integers
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");
        // Pad out r and s so that they are $keySize bits long
        $r = \str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = \str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);
        return $r . $s;
    }

    /**
     * @param $der
     * @param int $offset
     * @return array
     */
    protected function readDER($der, $offset = 0)
    {
        $pos         = $offset;
        $size        = \strlen($der);
        $constructed = (\ord($der[$pos]) >> 5) & 0x01;
        $type        = \ord($der[$pos++]) & 0x1f;

        // Length
        $len = \ord($der[$pos++]);
        if ($len & 0x80) {
            $n   = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | \ord($der[$pos++]);
            }
        }
        // Value
        if ($type == static::ASN1_BIT_STRING) {
            $pos++; // Skip the first contents octet (padding indicator)
            $data = \substr($der, $pos, $len - 1);
            $pos  += $len - 1;
        } elseif (!$constructed) {
            $data = \substr($der, $pos, $len);
            $pos  += $len;
        } else {
            $data = null;
        }

        return array($pos, $data);
    }

    /**
     * @param bool $sig
     * @return string
     */
    protected function signatureToDER(bool $sig)
    {
        // Separate the signature into r-value and s-value
        list($r, $s) = \str_split($sig, (int)(\strlen($sig) / 2));

        // Trim leading zeros
        $r = \ltrim($r, "\x00");
        $s = \ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (\ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (\ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }
        return static::encodeDER(
            static::ASN1_SEQUENCE,
            static::encodeDER(static::ASN1_INTEGER, $r) .
            static::encodeDER(static::ASN1_INTEGER, $s)
        );
    }

    /**
     * @param $type
     * @param $value
     * @return string
     */
    protected function encodeDER($type, $value)
    {
        $tag_header = 0;
        if ($type === static::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }
        // Type
        $der = \chr($tag_header | $type);
        // Length
        $der .= \chr(\strlen($value));
        return $der . $value;
    }

    /**
     * @param $msg
     * @param $signature
     * @param $key
     * @param $alg
     * @return bool
     */
    protected function verify($msg, $signature, $key, $alg)
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = static::$supported_algs[$alg];
        switch ($function) {
            case 'openssl':
                $success = \openssl_verify($msg, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new DomainException(
                    'OpenSSL error: ' . \openssl_error_string()
                );
            case 'sodium_crypto':
                if (!function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                try {
                    // The last non-empty line is used as the key.
                    $lines = array_filter(explode("\n", $key));
                    $key   = base64_decode(end($lines));
                    return \sodium_crypto_sign_verify_detached($signature, $msg, $key);
                } catch (Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }
            case 'hash_hmac':
            default:
                $hash = \hash_hmac($algorithm, $msg, $key, true);
                if (\function_exists('hash_equals')) {
                    return \hash_equals($signature, $hash);
                }
                $len = \min(StrHelper::byteLength($signature), StrHelper::byteLength($hash));

                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (\ord($signature[$i]) ^ \ord($hash[$i]));
                }
                $status |= (StrHelper::byteLength($signature) ^ StrHelper::byteLength($hash));

                return ($status === 0);
        }
    }

    /**
     * @param $input
     * @return mixed
     */
    protected function urlsafeB64Encode($input)
    {
        return \str_replace('=', '', \strtr(\base64_encode($input), '+/', '-_'));
    }

    /**
     * @param $input
     * @return bool|string
     */
    protected function urlsafeB64Decode($input)
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input  .= \str_repeat('=', $padlen);
        }
        return \base64_decode(\strtr($input, '-_', '+/'));
    }

}