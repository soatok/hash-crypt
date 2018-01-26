<?php
declare(strict_types=1);
namespace Soatok\HashCrypt;
use ParagonIE\ConstantTime\Binary;

/**
 * Class HashCrypt
 *
 * Transforms an arbitrary hash function into an AEAD cipher
 */
class HashCrypt
{
    /** @var string $algo */
    protected $algo = '';

    /** @var int $hSize */
    protected $hSize = 0;

    /** @var Key $key */
    protected $key;

    /**
     * HashCrypt constructor.
     *
     * @param string $algo
     * @param Key $key
     * @throws CryptoException
     */
    public function __construct(string $algo, Key $key)
    {
        if (!\in_array($algo, \hash_algos(), true)) {
            throw new CryptoException('Invalid hash function');
        }
        $this->algo = $algo;
        $this->hSize = \strlen(\hash($this->algo, '')) >> 1;
        $this->key = $key;
    }

    /**
     * @param string $plaintext
     * @param string $aad
     * @return string
     * @throws CryptoException
     * @throws \TypeError
     */
    public function encrypt(string $plaintext = '', string $aad = ''): string
    {
        try {
            $salt = \random_bytes($this->hSize);
            $nonce = \random_bytes($this->hSize >> 1);
        } catch (\Throwable $ex) {
            throw new CryptoException('Could not generate a random nonce');
        }
        return $this->aead_encrypt($plaintext, $aad, $salt, $nonce);
    }

    /**
     * @param string $ciphertext
     * @param string $aad
     * @return string
     * @throws CryptoException
     * @throws \TypeError
     */
    public function decrypt(string $ciphertext = '', string $aad = ''): string
    {
        $length = Binary::safeStrlen($ciphertext);
        $minLength = ($this->hSize * 3) - ($this->hSize >> 1);
        if ($length < $minLength) {
            throw new CryptoException('Message too short');
        }
        $salt = Binary::safeSubstr($ciphertext, 0, $this->hSize);
        $nonce = Binary::safeSubstr($ciphertext, $this->hSize, $this->hSize >> 1);

        $message = Binary::safeSubstr(
            $ciphertext,
            ($this->hSize * 2) - ($this->hSize >> 1),
            ($length - $minLength)
        );
        $mac = Binary::safeSubstr($ciphertext, $length - $this->hSize, $this->hSize);

        return $this->aead_decrypt($message, $aad, $salt, $nonce, $mac);
    }

    /**
     * Internal function made public for unit testing.
     *
     * @param string $plaintext
     * @param string $aad
     * @param string $salt
     * @param string $nonce
     * @return string
     * @throws CryptoException
     * @throws \TypeError
     */
    public function aead_encrypt(string $plaintext, string $aad, string $salt, string $nonce): string
    {
        if (Binary::safeStrlen($salt) !== $this->hSize) {
            throw new CryptoException('Invalid salt size');
        }
        if (Binary::safeStrlen($nonce) !== $this->hSize >> 1) {
            throw new CryptoException('Invalid nonce size');
        }
        list ($encKey, $authKey) = $this->splitKey($salt);

        $len = Binary::safeStrlen($plaintext);

        // Initialize our HMAC state with the authentication key
        $state = \hash_init($this->algo, HASH_HMAC, $authKey);

        // Feed the extended nonce into the HMAC
        \hash_update($state, $salt);
        \hash_update($state, $nonce);

        // Feed the length of the additional authenticated data, as a little-endian
        // 64-bit unsigned integer, into the HMAC before the AAD itself.
        \hash_update($state, \pack('P', \mb_strlen($aad)));
        \hash_update($state, $aad);

        // Feed the length of the message, as a little-endian 64-bit unsigned integer
        // into the HMAC before the ciphertext.
        \hash_update($state, \pack('P', $len));

        $ciphertext = '';
        $ctr = 0;
        for ($i = 0; $i < $len; $i += $this->hSize) {
            $chunk = Binary::safeSubstr($plaintext, $i, $this->hSize);
            $cLen = Binary::safeStrlen($chunk);
            $keystream = $this->streamBlock($encKey, $nonce, $ctr++);

            // Encrypt block
            $chunk = $chunk ^ Binary::safeSubstr($keystream, 0, $cLen);
            $ciphertext .= $chunk;

            // Update MAC state
            \hash_update($state, $chunk);
        }
        return $salt . $nonce . $ciphertext . \hash_final($state, true);
    }

    /**
     * Internal function made public for unit testing.
     *
     * @param string $ciphertext
     * @param string $aad
     * @param string $salt
     * @param string $nonce
     * @param string $mac
     * @return string
     * @throws CryptoException
     * @throws \TypeError
     */
    public function aead_decrypt(string $ciphertext, string $aad, string $salt, string $nonce, string $mac): string
    {
        if (Binary::safeStrlen($salt) !== $this->hSize) {
            throw new CryptoException('Invalid salt size');
        }
        if (Binary::safeStrlen($nonce) !== $this->hSize >> 1) {
            throw new CryptoException('Invalid nonce size');
        }
        list ($encKey, $authKey) = $this->splitKey($salt);

        $len = Binary::safeStrlen($ciphertext);

        // Recalculate the HMAC of the ciphertext:
        $state = \hash_init($this->algo, HASH_HMAC, $authKey);
        \hash_update($state, $salt);
        \hash_update($state, $nonce);
        \hash_update($state, \pack('P', Binary::safeStrlen($aad)));
        \hash_update($state, $aad);
        \hash_update($state, \pack('P', $len));
        \hash_update($state, $ciphertext);
        $calcMac = \hash_final($state, true);

        // Validate the MAC. Fail if it doesn't match.
        if (!\hash_equals($calcMac, $mac)) {
            throw new CryptoException('Invalid message authentication code');
        }

        // Let's decrypt the message
        $plaintext = '';
        $ctr = 0;
        for ($i = 0; $i < $len; $i += $this->hSize) {
            $chunk = Binary::safeSubstr($ciphertext, $i, $this->hSize);
            $cLen = Binary::safeStrlen($chunk);
            $keystream = $this->streamBlock($encKey, $nonce, $ctr++);

            // Decrypt block
            $plaintext .= $chunk ^ Binary::safeSubstr($keystream, 0, $cLen);
        }
        return $plaintext;
    }

    /**
     * We're converting our key, nonce, and counter into blocks of a keystream
     * in order to create a stream cipher.
     *
     * @param string $key
     * @param string $nonce
     * @param int $ctr
     * @return string
     */
    public function streamBlock(string $key, string $nonce, int $ctr): string
    {
        return \hash(
            $this->algo,
            $nonce . \pack('P', $ctr) . $key,
            true
        );
    }

    /**
     * Get the size of the hash function being used.
     *
     * @return int
     */
    public function getHashSize(): int
    {
        return $this->hSize;
    }

    /**
     * Split a key, using domain separation, into an Encryption Key
     * and an Authentication Key.
     *
     * The domain separation constants are the bitwise inverses of the
     * ipad and opad byte values for the HMAC standard (0x36 and 0x5c).
     *
     * @param string $salt
     * @return array<int, string>
     */
    public function splitKey(string $salt): array
    {
        return [
            \hash_hmac(
                $this->algo,
                \str_repeat("\xa3", $this->hSize) . $salt,
                $this->key->getKey(),
                true
            ),
            \hash_hmac(
                $this->algo,
                \str_repeat("\xc9", $this->hSize) . $salt,
                $this->key->getKey(),
                true
            )
        ];
    }
}
