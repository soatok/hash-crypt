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
            '1161ac6ea834fb85c29ec05d51d8b16b',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '37fa2b8ae289495639d35c396346940e',
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
            '610947912d2bf10a0e27a94be541110464b660e3a539' .
            'cfc2fffa5b48554291cca6d07fcc31fe',
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
            '61094c912d2bf10a0e27a94be541110464b660e3a539' .
            '73362b798948866daf880baf64e1a0e3',
            bin2hex($ciphertext)
        );

        $this->assertSame(40, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(40, Binary::safeStrlen($hashCrypt->encrypt('', 'dhole')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('', 'dhole'), 'dhole'));
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
                '61094c912d2bf10a0e27a94be541110464b660e3a539' .
                'cfc2fffa5b48554291cca6d07fcc31fe'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0302020202020202' .
                '61094c912d2bf10a0e27a94be541110464b660e3a539' .
                'cfc2fffa5b48554291cca6d07fcc31fe'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0202020202020202' .
                '62094c912d2bf10a0e27a94be541110464b660e3a539' .
                'cfc2fffa5b48554291cca6d07fcc31fe'
            ),
            hex2bin(
                '01010101010101010101010101010101' .
                '0202020202020202' .
                '61094c912d2bf10a0e27a94be541110464b660e3a539' .
                'd0c2fffa5b48554291cca6d07fcc31fe'
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
            'b63e6869599dbcaf809f6fa05b3599e70378243d',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            'f8742851c7f9b472ca2d628e7cb936c3091e4a1d',
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
            '35f0c5f6c0833ca29922856c5401fdeeb4c42270c933' .
            '12541043703cb4d38460100e049db4c812cfb554',
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
            '35f0cef6c0833ca29922856c5401fdeeb4c42270c933' .
            'ca75008599870b79fe4a2786cca1435c224774a6',
            bin2hex($ciphertext)
        );

        $this->assertSame(50, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(50, Binary::safeStrlen($hashCrypt->encrypt('', 'dhole')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('', 'dhole'), 'dhole'));
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
                '35f0c5f6c0833ca29922856c5401fdeeb4c42270c933' .
                '12541043703cb4d38460100e049db4c812cfb554'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '03020202020202020202' .
                '35f0c5f6c0833ca29922856c5401fdeeb4c42270c933' .
                '12541043703cb4d38460100e049db4c812cfb554'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '02020202020202020202' .
                '36f0c5f6c0833ca29922856c5401fdeeb4c42270c933' .
                '12541043703cb4d38460100e049db4c812cfb554'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101' .
                '02020202020202020202' .
                '35f0c5f6c0833ca29922856c5401fdeeb4c42270c933' .
                '13541043703cb4d38460100e049db4c812cfb554'
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
            '0a0c060ab855dd1f8bc03b2ccb7ed381de6ee74ef70b7e02ace896425189e413',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '7093f5e4ffcc4161f46545c998fff396fb428bb2927026bf3d71d7d86667e01e',
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
            'b8e69a4c868b3e62423c381d15cd0be0fefa325c10a3' .
            'cf19c0cb50eb00739500fde6410260522f167e92822af9129c9e6e761a5ac514',
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
            'b8e6914c868b3e62423c381d15cd0be0fefa325c10a3' .
            'cca858c3f045336c79e6304d4b0ce5dc0a6bcd99f3eaf5525793d0b0d02f9315',
            bin2hex($ciphertext)
        );

        $this->assertSame(80, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(80, Binary::safeStrlen($hashCrypt->encrypt('', 'dhole')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('', 'dhole'), 'dhole'));
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
                'b8e69a4c868b3e62423c381d15cd0be0fefa325c10a3' .
                'cf19c0cb50eb00739500fde6410260522f167e92822af9129c9e6e761a5ac514'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '03020202020202020202020202020202' .
                'b8e69a4c868b3e62423c381d15cd0be0fefa325c10a3' .
                'cf19c0cb50eb00739500fde6410260522f167e92822af9129c9e6e761a5ac514'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '02020202020202020202020202020202' .
                'b9e69a4c868b3e62423c381d15cd0be0fefa325c10a3' .
                'cf19c0cb50eb00739500fde6410260522f167e92822af9129c9e6e761a5ac514'
            ),
            hex2bin(
                '0101010101010101010101010101010101010101010101010101010101010101' .
                '02020202020202020202020202020202' .
                'b8e69a4c868b3e62423c381d15cd0be0fefa325c10a3' .
                'd019c0cb50eb00739500fde6410260522f167e92822af9129c9e6e761a5ac514'
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
            '00a42234ddf3db620f3b95f2713ef0216f91b01c3b88b5fc382285eb80d2fcb1c168493eb7b4b1418ffba8948efa3048',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            'ad4951b8ecfdc04fb281e7ea756c2ab35ced15840ca4b719adeb71c48ff74b5308187a50362a1f4ad5e40ecd7cdea233',
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
            'abbbaf43aa43cf5295d276252e7b0b5bfd338a132785' .
            '78bd8c8eb9579ae84fd2c8e6dc186ed43ac7d53dd5c943dcfdb0ecaa6fe8267e3a79116f9fcf141e992e0434520e041b',
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
            'abbba443aa43cf5295d276252e7b0b5bfd338a132785' .
            '9602f38b31a404dc1b4cf23632b526201cf70c33491421ed60f5a6fadb2208c76c3c1c3aa7734e2018bf7a9138b1cdd5',
            bin2hex($ciphertext)
        );


        $this->assertSame(120, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(120, Binary::safeStrlen($hashCrypt->encrypt('', 'dhole')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('', 'dhole'), 'dhole'));
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
                'abbbaf43aa43cf5295d276252e7b0b5bfd338a132785' .
                '78bd8c8eb9579ae84fd2c8e6dc186ed43ac7d53dd5c943dcfdb0ecaa6fe8267e3a79116f9fcf141e992e0434520e041b'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '030202020202020202020202020202020202020202020202' .
                'abbbaf43aa43cf5295d276252e7b0b5bfd338a132785' .
                '78bd8c8eb9579ae84fd2c8e6dc186ed43ac7d53dd5c943dcfdb0ecaa6fe8267e3a79116f9fcf141e992e0434520e041b'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '020202020202020202020202020202020202020202020202' .
                'acbbaf43aa43cf5295d276252e7b0b5bfd338a132785' .
                '78bd8c8eb9579ae84fd2c8e6dc186ed43ac7d53dd5c943dcfdb0ecaa6fe8267e3a79116f9fcf141e992e0434520e041b'
            ),
            hex2bin(
                '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '020202020202020202020202020202020202020202020202' .
                'abbbaf43aa43cf5295d276252e7b0b5bfd338a132785' .
                '79bd8c8eb9579ae84fd2c8e6dc186ed43ac7d53dd5c943dcfdb0ecaa6fe8267e3a79116f9fcf141e992e0434520e041b'
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
            '2687d92561fe48ee06b5441f825495df1f151388824f746a0690121571b8381ac398ce5db38f21da77e656c4ba83b4db4fd8ca8f93b55c75c201fa36d176ab62',
            bin2hex($hashCrypt->streamBlock($key->getKey(), $nonce, 0))
        );
        $this->assertSame(
            '5b717a4f934b9b35505125b608464c6a84e43bc20270ae3ee6bad8d90fed3a641a8b52b15fce5113be944f1fe351e6f2984b52787620efa04dc73e9dded888b9',
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
            '87856cc59186a40f9fcfb65deefb1b30fb7f4d22c690' .
            '6aa4217024e11850f431f6fbb75db806fcee00f8f34c4cb0de9bf4269f613fce9ec46f51fac9d47db452d9d67a2fedae42537bd7ebd1d12a75fb43d876e676eb',
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
            '878567c59186a40f9fcfb65deefb1b30fb7f4d22c690' .
            '2c1f04c6b5bc3fe018895a88fcbe79e4d12bf2c45de240fa201b83faafb3063294219887618667b16cd62b2dad3cbbfd8cf5ab51eb8262d97d6d1827126d6e3f',
            bin2hex($ciphertext)
        );


        $this->assertSame(160, Binary::safeStrlen($hashCrypt->encrypt('')));
        $this->assertSame(160, Binary::safeStrlen($hashCrypt->encrypt('', 'dhole')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('')));
        $this->assertSame('', $hashCrypt->decrypt($hashCrypt->encrypt('', 'dhole'), 'dhole'));
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
                '87856cc59186a40f9fcfb65deefb1b30fb7f4d22c690' .
                '6aa4217024e11850f431f6fbb75db806fcee00f8f34c4cb0de9bf4269f613fce9ec46f51fac9d47db452d9d67a2fedae42537bd7ebd1d12a75fb43d876e676eb'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0302020202020202020202020202020202020202020202020202020202020202' .
                '87856cc59186a40f9fcfb65deefb1b30fb7f4d22c690' .
                '6aa4217024e11850f431f6fbb75db806fcee00f8f34c4cb0de9bf4269f613fce9ec46f51fac9d47db452d9d67a2fedae42537bd7ebd1d12a75fb43d876e676eb'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0202020202020202020202020202020202020202020202020202020202020202' .
                '88856cc59186a40f9fcfb65deefb1b30fb7f4d22c690' .
                '6aa4217024e11850f431f6fbb75db806fcee00f8f34c4cb0de9bf4269f613fce9ec46f51fac9d47db452d9d67a2fedae42537bd7ebd1d12a75fb43d876e676eb'
            ),
            hex2bin(
                '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101' .
                '0202020202020202020202020202020202020202020202020202020202020202' .
                '87856cc59186a40f9fcfb65deefb1b30fb7f4d22c690' .
                '6ba4217024e11850f431f6fbb75db806fcee00f8f34c4cb0de9bf4269f613fce9ec46f51fac9d47db452d9d67a2fedae42537bd7ebd1d12a75fb43d876e676eb'
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