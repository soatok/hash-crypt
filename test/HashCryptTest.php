<?php
namespace Soatok\HashCrypt\Tests;

use ParagonIE\ConstantTime\Binary;
use PHPUnit\Framework\TestCase;
use Soatok\HashCrypt\CryptoException;
use Soatok\HashCrypt\HashCrypt;
use Soatok\HashCrypt\Key;

class HashCryptTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws \TypeError
     */
    public function testMd5Crypt()
    {
        $salt = str_repeat("\x01", 16);
        $nonce = str_repeat("\x02", 8);
        $key = new Key(str_repeat("\x80", 16));

        $hashCrypt = new HashCrypt('md5', $key);

        $this->assertSame(
            '64b240cf0d6aab81f9ed1d99a15c6d90',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '64014c89969d1e0bec733ca07e406dff',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 1))
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'test message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '01010101010101010101010101010101' .
            '0202020202020202' .
            '68ec815361a185e92d6416366dadce398131d9c6db4d' .
            'b0ab15f7cc21e5d9289b8e85bfcb15e0',
            bin2hex($ciphertext)
        );
        $ciphertext = $hashCrypt->aead_encrypt(
            'text message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '01010101010101010101010101010101' .
            '0202020202020202' .
            '68ec8a5361a185e92d6416366dadce398131d9c6db4d' .
            'dcaa9db02ba7d056a44b0df24f2f94dd',
            bin2hex($ciphertext)
        );

        $this->assertSame(40, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(
            'test message goes here',
            $hashCrypt->decrypt($hashCrypt->encrypt('test message goes here'))
        );
        $this->assertNotSame(
            $hashCrypt->encrypt('test message goes here', 'aad'),
            $hashCrypt->encrypt('test message goes here')
        );
        $invalids = [
            hex2bin(
                '02010101010101010101010101010101' .
                '0202020202020202' .
                '68ec815361a185e92d6416366dadce398131d9c6db4d' .
                'b0ab15f7cc21e5d9289b8e85bfcb15e0'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0302020202020202' .
                '68ec815361a185e92d6416366dadce398131d9c6db4d' .
                'b0ab15f7cc21e5d9289b8e85bfcb15e0'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0202020202020202' .
                '69ec815361a185e92d6416366dadce398131d9c6db4d' .
                'b0ab15f7cc21e5d9289b8e85bfcb15e0'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0202020202020202' .
                '68ec815361a185e92d6416366dadce398131d9c6db4d' .
                'b1ab15f7cc21e5d9289b8e85bfcb15e0'
            )
        ];

        foreach ($invalids as $i => $invalid) {
            try {
                $hashCrypt->decrypt($invalid);
                $this->fail('Invalid MAC accepted for row ' . $i);
            } catch (CryptoException $ex) {
                $this->assertSame('Invalid message authentication code', $ex->getMessage());
            }
        }
    }

    /**
     * @throws CryptoException
     * @throws \TypeError
     */
    public function testSha1Crypt()
    {
        $salt = str_repeat("\x01", 20);
        $nonce = str_repeat("\x02", 10);
        $key = new Key(str_repeat("\x80", 20));

        $hashCrypt = new HashCrypt('sha1', $key);

        $this->assertSame(
            '1e6927a92fbb7f7aebef33abb0e4f760fd07f19b',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '1ca446ea496c909426f3e791d080a7ca95e7d682',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 1))
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'test message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '0101010101010101010101010101010101010101' .
            '02020202020202020202' .
            '5d356ffa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
            'e0d0374fe9d160426775169714bd14aa47f8d6ad',
            bin2hex($ciphertext)
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'text message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '0101010101010101010101010101010101010101' .
            '02020202020202020202' .
            '5d3564fa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
            '7bb8257d506fb0b584552b306099e25ec96169b0',
            bin2hex($ciphertext)
        );

        $this->assertSame(50, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(
            'test message goes here',
            $hashCrypt->decrypt($hashCrypt->encrypt('test message goes here'))
        );
        $this->assertNotSame(
            $hashCrypt->encrypt('test message goes here', 'aad'),
            $hashCrypt->encrypt('test message goes here')
        );
        $invalids = [
            hex2bin(
                '0201010101010101010101010101010101010101' .
                '02020202020202020202' .
                '5d356ffa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
                'e0d0374fe9d160426775169714bd14aa47f8d6ad'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '03020202020202020202' .
                '5d356ffa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
                'e0d0374fe9d160426775169714bd14aa47f8d6ad'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '02020202020202020202' .
                '5e356ffa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
                'e0d0374fe9d160426775169714bd14aa47f8d6ad'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '02020202020202020202' .
                '5d356ffa5fc72921e3cc8e55a9f63cb67d2725a2473a' .
                'e1d0374fe9d160426775169714bd14aa47f8d6ad'
            )
        ];

        foreach ($invalids as $i => $invalid) {
            try {
                $hashCrypt->decrypt($invalid);
                $this->fail('Invalid MAC accepted for row ' . $i);
            } catch (CryptoException $ex) {
                $this->assertSame('Invalid message authentication code', $ex->getMessage());
            }
        }
    }


    /**
     * @throws CryptoException
     * @throws \TypeError
     */
    public function testSha256Crypt()
    {
        $salt = str_repeat("\x01", 32);
        $nonce = str_repeat("\x02", 16);
        $key = new Key(str_repeat("\x80", 32));

        $hashCrypt = new HashCrypt('sha256', $key);

        $this->assertSame(
            '4cb9255ec7a9bb1db22e3148741f3e5f64fd93156a6c8e1852a3f05fbd509b55',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '46b13a4db8e05abc5f0a6e5caf38c4c2dc4c451c30d348e5792c09677aacc1da',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 1))
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'test message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '0101010101010101010101010101010101010101010101010101010101010101' .
            '02020202020202020202020202020202' .
            '52c5757d6a51c69d022096d09841a16c1e65a19631b2' .
            'ba43bd00ab713575d176d6406c7a131fb2b1786fae54f03da725bfd4d61489e4',
            bin2hex($ciphertext)
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'text message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '0101010101010101010101010101010101010101010101010101010101010101' .
            '02020202020202020202020202020202' .
            '52c57e7d6a51c69d022096d09841a16c1e65a19631b2' .
            '98c10f0321509b450636063558ac4f67c054b9d0938ac52a8ed88c8cf7b48045',
            bin2hex($ciphertext)
        );

        $this->assertSame(80, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(
            'test message goes here',
            $hashCrypt->decrypt($hashCrypt->encrypt('test message goes here'))
        );
        $this->assertNotSame(
            $hashCrypt->encrypt('test message goes here', 'aad'),
            $hashCrypt->encrypt('test message goes here')
        );
        $invalids = [
            hex2bin(
                '0201010101010101010101010101010101010101010101010101010101010101' .
                '02020202020202020202020202020202' .
                '52c5757d6a51c69d022096d09841a16c1e65a19631b2' .
                'ba43bd00ab713575d176d6406c7a131fb2b1786fae54f03da725bfd4d61489e4'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '03020202020202020202020202020202' .
                '52c5757d6a51c69d022096d09841a16c1e65a19631b2' .
                'ba43bd00ab713575d176d6406c7a131fb2b1786fae54f03da725bfd4d61489e4'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '02020202020202020202020202020202' .
                '53c5757d6a51c69d022096d09841a16c1e65a19631b2' .
                'ba43bd00ab713575d176d6406c7a131fb2b1786fae54f03da725bfd4d61489e4'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '02020202020202020202020202020202' .
                '52c5757d6a51c69d022096d09841a16c1e65a19631b2' .
                'ca43bd00ab713575d176d6406c7a131fb2b1786fae54f03da725bfd4d61489e4'
            )
        ];

        foreach ($invalids as $i => $invalid) {
            try {
                $hashCrypt->decrypt($invalid);
                $this->fail('Invalid MAC accepted for row ' . $i);
            } catch (CryptoException $ex) {
                $this->assertSame('Invalid message authentication code', $ex->getMessage());
            }
        }
    }

    /**
     * @throws CryptoException
     * @throws \TypeError
     */
    public function testSha384Crypt()
    {
        $salt = str_repeat("\x01", 48);
        $nonce = str_repeat("\x02", 24);
        $key = new Key(str_repeat("\x80", 48));

        $hashCrypt = new HashCrypt('sha384', $key);

        $this->assertSame(
            'c5837806983bbe95ab98c93272350ec8babab0a4d4c8ad58deea2aab285cab3a05cd3250f12a01853417676b8209f04c',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            'b60743203466e4c8470edb7de72f32232b6464b96bd5d6625deb0f169d7badd00aa5586d609c1c9b776fbce0436920e8',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 1))
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'test message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
            '020202020202020202020202020202020202020202020202' .
            '7626176b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
            'b3a06d3e5633a0f1e0a4ab0e66f7fdfac8b7e5481c9b18c873c3ee823c6b47ab697b43b01a4ead971ae1077cb4a38bab',
            bin2hex($ciphertext)
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'text message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
            '020202020202020202020202020202020202020202020202' .
            '76261c6b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
            '0cdf3f01808a9dc13ff180990c4bcfa9cecd1df019b3b49b937f92cd3449b2ca2d832031dafda26427305fd41aa59f28',
            bin2hex($ciphertext)
        );


        $this->assertSame(120, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(
            'test message goes here',
            $hashCrypt->decrypt($hashCrypt->encrypt('test message goes here'))
        );
        $this->assertNotSame(
            $hashCrypt->encrypt('test message goes here', 'aad'),
            $hashCrypt->encrypt('test message goes here')
        );
        $invalids = [
            hex2bin(
                '020101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '020202020202020202020202020202020202020202020202' .
                '7626176b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
                'b3a06d3e5633a0f1e0a4ab0e66f7fdfac8b7e5481c9b18c873c3ee823c6b47ab697b43b01a4ead971ae1077cb4a38bab'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '030202020202020202020202020202020202020202020202' .
                '7626176b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
                'b3a06d3e5633a0f1e0a4ab0e66f7fdfac8b7e5481c9b18c873c3ee823c6b47ab697b43b01a4ead971ae1077cb4a38bab'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '020202020202020202020202020202020202020202020202' .
                '7726176b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
                'b3a06d3e5633a0f1e0a4ab0e66f7fdfac8b7e5481c9b18c873c3ee823c6b47ab697b43b01a4ead971ae1077cb4a38bab'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '020202020202020202020202020202020202020202020202' .
                '7626176b9311bed7e08ca1ef3ac5e30cb653f46a8796' .
                'b4a06d3e5633a0f1e0a4ab0e66f7fdfac8b7e5481c9b18c873c3ee823c6b47ab697b43b01a4ead971ae1077cb4a38bab'
            )
        ];

        foreach ($invalids as $i => $invalid) {
            try {
                $hashCrypt->decrypt($invalid);
                $this->fail('Invalid MAC accepted for row ' . $i);
            } catch (CryptoException $ex) {
                $this->assertSame('Invalid message authentication code', $ex->getMessage());
            }
        }
    }

    /**
     * @throws CryptoException
     * @throws \TypeError
     */
    public function testSha512Crypt()
    {
        $salt = str_repeat("\x01", 64);
        $nonce = str_repeat("\x02", 32);
        $key = new Key(str_repeat("\x80", 64));

        $hashCrypt = new HashCrypt('sha512', $key);

        $this->assertSame(
            'e9013157da7757ee1af75590fa0e6886cd37433b982dba46b450bf889c72cd58dcbd3dd837beba177c8d15397ce41b7fce94bea6f7b0f553a4d3a3366f081d1d',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '856ac4bb8469de93c84c4f1b8cf425e424d957b341eed2c4cd6202bef0de1848ef1fd57f14ab888c5cea71ac0fadd703729e70b5cf495729548f5fa8fa411e42',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 1))
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'test message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
            '0202020202020202020202020202020202020202020202020202020202020202' .
            '1a7907cd5232ae21a75156359f7037b6b1d4358b8322' .
            '0c8fb9e88ba22a7abb383b5c42260fb3f66953abf807f52aba97db23e801e0b68a970c667dd7855af3b4e5833aa609ae03b60183dfd3d1425a30f9ed0c1a8a09',
            bin2hex($ciphertext)
        );

        $ciphertext = $hashCrypt->aead_encrypt(
            'text message goes here',
            '',
            $salt,
            $nonce
        );
        $this->assertSame(
            '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
            '0202020202020202020202020202020202020202020202020202020202020202' .
            '1a790ccd5232ae21a75156359f7037b6b1d4358b8322' .
            'cd60993380df002d1a764027ee11ac0360862a9cd72dd84561df2972ff4ac173f2c6c39934c335b2a0a007d54fe644490ffc6f0e3b2499f2bd49d7ccb251bee0',
            bin2hex($ciphertext)
        );


        $this->assertSame(160, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(
            'test message goes here',
            $hashCrypt->decrypt($hashCrypt->encrypt('test message goes here'))
        );
        $this->assertNotSame(
            $hashCrypt->encrypt('test message goes here', 'aad'),
            $hashCrypt->encrypt('test message goes here')
        );
        $invalids = [
            hex2bin(
                '02010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0202020202020202020202020202020202020202020202020202020202020202' .
                '1a7907cd5232ae21a75156359f7037b6b1d4358b8322' .
                '0c8fb9e88ba22a7abb383b5c42260fb3f66953abf807f52aba97db23e801e0b68a970c667dd7855af3b4e5833aa609ae03b60183dfd3d1425a30f9ed0c1a8a09'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0302020202020202020202020202020202020202020202020202020202020202' .
                '1a7907cd5232ae21a75156359f7037b6b1d4358b8322' .
                '0c8fb9e88ba22a7abb383b5c42260fb3f66953abf807f52aba97db23e801e0b68a970c667dd7855af3b4e5833aa609ae03b60183dfd3d1425a30f9ed0c1a8a09'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0202020202020202020202020202020202020202020202020202020202020202' .
                '1b7907cd5232ae21a75156359f7037b6b1d4358b8322' .
                '0c8fb9e88ba22a7abb383b5c42260fb3f66953abf807f52aba97db23e801e0b68a970c667dd7855af3b4e5833aa609ae03b60183dfd3d1425a30f9ed0c1a8a09'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0202020202020202020202020202020202020202020202020202020202020202' .
                '1a7907cd5232ae21a75156359f7037b6b1d4358b8322' .
                '0d8fb9e88ba22a7abb383b5c42260fb3f66953abf807f52aba97db23e801e0b68a970c667dd7855af3b4e5833aa609ae03b60183dfd3d1425a30f9ed0c1a8a09'
            )
        ];

        foreach ($invalids as $i => $invalid) {
            try {
                $hashCrypt->decrypt($invalid);
                $this->fail('Invalid MAC accepted for row ' . $i);
            } catch (CryptoException $ex) {
                $this->assertSame('Invalid message authentication code', $ex->getMessage());
            }
        }
    }
}