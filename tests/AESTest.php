<?php declare (strict_types = 1);

namespace CrudeCrypto\Tests;

use CrudeCrypto\AES;
use CrudeCrypto\Hex;
use CrudeCrypto\PKCS7;
use CrudeCrypto\Tests\Assertions\BinaryStringAssertion;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use TypeError;

final class AESTest extends TestCase {
  use BinaryStringAssertion;

  const MODE_CIPHER_CBC = (0b001 << 0);
  const MODE_CIPHER_MASK = (0b111 << 0);
  const MODE_BITS_128 = (0b001 << 3);
  const MODE_BITS_192 = (0b010 << 3);
  const MODE_BITS_256 = (0b011 << 3);
  const MODE_BITS_MASK = (0b111 << 3);
  const MODE_PADDING_NONE = (0b000 << 6);
  const MODE_PADDING_PKCS7 = (0b001 << 6);
  const MODE_PADDING_MASK = (0b111 << 6);

  public static function encryptionProvider(): array {
    return [
      'aes-128-cbc,    no padding, 16-byte key,   16-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => 'f5 50 e8 4f e0 4d d8 24 5f 99 fc 7f ce 5a 3d 7a',
        'in' => 'f4 0a 03 84 77 69 87 54 ed e0 ac a4 72 f1 57 7d',
        'out' => '5d 0e 09 b7 d0 00 26 31 c7 ad bb 82 ca b5 17 15',
      ]],
      'aes-128-cbc,    no padding, 16-byte key,   15-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => '45 f0 14 74 9e 6b c5 aa e2 85 74 05 d4 c4 76 81',
        'in' => '92 3d 81 94 41 04 3b 26 6c bf 51 56 90 6c 53',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidInputSizeException', 'input must be a multiple of 16 bytes'],
      ]],
      'aes-128-cbc,    no padding, 15-byte key,   16-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => '43 c2 1c b7 5e 3b 09 38 4e bd 70 54 3d 1b df',
        'in' => '99 46 1c f3 8b d2 3f 96 68 06 4c da 9a 97 82 d8',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 16 bytes long'],
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,    4-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '28 c2 5c e4 47 d6 e5 1b 0a b4 bc 20 e4 59 82 64',
        'in' => 'd3 73 93 18',
        'out' => 'f8 79 bc a2 70 33 4f 97 23 d1 e8 45 38 ae 9b d5',
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,   15-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => 'c7 fc f6 80 04 77 67 6e de 63 82 a9 99 a9 0c b7',
        'iv' => '34 a8 03 55 67 1d fd 5b 1f 81 82 2d 9a 0b 70 ca',
        'in' => '0a 39 e6 12 e5 3e 5e 67 36 f2 ba b8 fe 6c f4',
        'out' => 'bb 80 2f 53 db 03 27 81 ee bc 53 da 7d ad 9f 6c',
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,   15-byte input,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '82 00 f4 6c 9e 73 26 78 d2 5e 95 4b ad c9 78 97',
        'iv' => '6c a8 dd 10 8a d8 03 36',
        'in' => 'bb 32 98 88 d5 41 05 ff bf 1d 2f 33 14 05 ba',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,  255-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '02 0d 21 51 18 b9 d3 b1 7d 05 b5 8d 27 98 ce b7',
        'in' => 'c1 23 8a 68 b1 5c 40 1c cb 80 e1 57 1b c9 fe 95 25 6e 0b 79 df a2 2e 97 0c 32 29 1f 88 61 39 62 dc ec 60 03 8f c6 71 be 7e d2 88 01 2c cd 63 71 22 4d fc 28 a8 16 66 d1 05 70 0e e6 d2 33 6e a6 e8 23 7b 55 2e 81 62 17 73 ab f7 61 b6 5f 18 06 d0 78 60 1e e4 4c 39 f7 45 95 c1 cb 79 2a 0b ac ac d7 9e 4e 07 22 c9 a8 0b 2b b4 dd c9 1e 50 92 82 0d 20 43 93 dd 54 7d 05 02 30 fe 7f 31 0a a0 8b c8 e9 78 71 fe 3d c7 99 e1 b7 e8 c6 cb 07 4b db 8f 75 78 dc 06 3d 98 43 f0 5f 44 4a 67 a0 8f be d4 34 b6 1a b1 bb 50 ea e1 6d a3 23 db 1d b8 59 7e d9 54 f4 40 56 9e 7f f7 4b 42 ba 5f 23 d1 3d 96 cc 1d 27 9d a2 24 b7 62 65 a3 7c 4b b2 d0 f8 16 12 aa 1b 91 cb fd cf 90 c9 38 b6 33 47 ea 3c f5 70 ac 1b 7f aa ca 4e db 6a e1 ed db f2 7c c2 38 94 5f 01 13 1c 5a ee dd 18 d2 90 b8 60',
        'out' => '83 4a d2 03 be 0f 8d cc 3c da da 6f c2 55 5b f1 b9 f4 19 0f 6e 5a 98 74 04 ae 99 94 2d a6 7c 9b 1d c0 19 ed 7c c1 25 e0 df ab 56 27 45 30 ef 63 2c 26 77 3c 43 d9 13 3a 0d 01 65 4a 5e ac dc e0 53 d5 7c 34 04 b7 c9 d0 98 c3 87 e1 0e 78 b9 72 d2 aa 92 51 b7 4e b1 70 37 a8 85 58 c0 d3 2d 25 fa 64 5f 59 c7 8c 42 ce dd 44 50 5b 3e 1e e1 50 f3 31 32 57 19 91 0d 6f 8c 47 10 1b 87 0d fa 6e 2c f1 b4 91 56 3d 41 30 d8 47 bf 47 5b c7 fa 0d 98 6a 67 e8 21 54 1a 2d 7b 4f 72 53 d7 14 dc b6 f5 96 b2 88 47 0e 42 c3 a5 8e d7 b2 88 3a fe be 62 a4 ff 0d 35 9e 1d 75 cf 6c 5d 62 86 13 e7 ad 01 6e d3 db 8a 89 e6 2d 1e da 8b 92 26 17 cb 67 aa 08 5d cc 9f 23 a5 c2 1c 6a b5 d6 80 a8 10 aa 30 d4 56 53 86 a3 0f d3 7d ad 7d e2 a4 16 23 70 15 8d 2c e5 d9 52 72 fc 2e 2a fc f5 c7 2f b0 f4',
      ]],
      'aes-128-cbc,    no padding, 16-byte key,  256-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => 'c4 5d c5 c5 28 33 eb d9 75 3e 4a 3e 2f 0f a4 57',
        'iv' => 'bf 23 ad 83 7d d9 7b b4 f7 b5 ba 60 96 16 e3 8f',
        'in' => '60 1c 80 49 c7 75 ef af 1f 7d 3a 2b c2 a2 b2 bf c5 0c ce 3a e3 60 94 78 d1 42 32 1b 8e 36 27 c5 bc 57 6b 50 de 03 41 56 9a 6c 04 33 cb e2 a7 c8 09 7c 28 26 33 66 95 90 4f cb e9 ab 72 4b e3 f6 ad 42 03 29 18 b8 4d 9b 6a 4b d7 70 a4 1a 8e a5 2e 4d 98 0a fa ca a4 0e 4c d3 45 11 61 5b d7 4e e7 5a 07 21 f4 6a 75 f6 e7 15 29 d2 de 0f 6a ee 32 5a 20 fe 37 b3 b3 e2 ac b3 f2 73 06 14 54 76 a4 75 79 c5 c0 dd fb 58 e3 58 c1 1c 73 ff e2 0c ce e3 a1 7f df 60 0c 6f 09 d9 79 92 6d 8c bb dc 08 28 8c 33 92 0d 7c 0d d7 d2 b4 1c 36 49 56 64 1e 95 19 c4 db f9 c2 5a 18 10 8e 49 a9 31 13 91 b3 95 ad 8d bb 68 8f 65 fe 9f bc db f5 3d f8 75 97 9c af 4d d1 c5 56 8c 3b 39 67 01 7a 60 07 fe 28 94 78 08 93 f5 37 1e 6a 72 5f 42 3b 47 f2 9a 30 79 92 34 e4 4e 0a b2 86 4b af df ab 0b ba 5b',
        'out' => 'e5 d9 82 e2 6e d9 90 56 e0 11 40 07 ad 9a 6e e8 0a b4 da 9b 34 07 d9 bb 42 a1 df bd 87 cc f0 94 ac 61 df e9 c7 84 88 62 ee 9e a2 ea a6 37 9e d7 e7 be 4c 5f 08 50 98 13 0d 98 b6 bc 2e 95 6d c1 87 56 03 50 14 28 b7 16 31 96 ec b4 01 8e c9 ef b4 6c 3b b8 da e9 1e 97 c0 8a 3d 60 b1 00 1c 8d cd 28 19 03 2c 4e 90 89 9f 3f 43 dd e0 4d 9a 63 ea 53 c9 d3 bc b4 3a 2c 93 09 75 44 33 d1 c0 35 7a f0 1e d5 f7 f3 b9 a3 b6 1f ac a7 c3 1c 89 9a 8b 14 50 ed 2c bb 7d fc 11 49 a1 29 f9 a1 a6 5f 6a f9 0b 9c a3 cb cc e6 65 7e d3 08 f2 1d c7 88 4f 61 89 31 23 73 37 93 48 2c e2 db 83 cd 78 df 1d 55 13 a0 dd 0c 52 62 25 92 08 4c 54 44 5a e3 7c 86 45 ef 5d ab 90 01 e7 0a ae 0d 32 3c b0 d5 ca 87 8e 31 6c ae 4f 97 6e b9 b9 e2 82 c0 5c ee 22 e4 f1 80 65 f8 0a 23 6e f7 de cc 39 9a 32 cb',
      ]],

      /* -------------------------------------------------- */

      'aes-192-cbc,    no padding, 24-byte key,   16-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '08 19 45 0f fc bc be 77 66 06 f1 c3 15 db 63 91 f0 f4 7d 20 60 29 68 a4',
        'in' => '7d c4 22 4e 03 12 70 93 be 4d 3d c0 6c 07 ab ce',
        'out' => 'c6 04 6c a6 3c e9 e8 1b a2 66 ef bf d1 d2 d7 79',
      ]],
      'aes-192-cbc,    no padding, 24-byte key,   15-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => 'c0 fc 7b b8 f8 22 b9 dc 9e af 21 74 4f c8 2e df f7 f1 5e 1e 91 54 d5 aa',
        'in' => '0a 1a 24 01 95 f1 e9 d7 8a 70 c8 28 ca 62 51',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidInputSizeException', 'input must be a multiple of 16 bytes'],
      ]],
      'aes-192-cbc,    no padding, 23-byte key,   16-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '36 ff 99 fa a6 c9 1c b4 11 ae 23 59 a9 7b 46 f8 dd a8 61 d0 95 85 43',
        'in' => '9b 97 4b 1f c1 91 99 53 da 3a cf dd 08 49 f2 bd',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 24 bytes long'],
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,    4-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '93 a3 ae 0c ae 1a 8a a6 b0 6e eb 9c 90 5e fe 4d ed dd ad 88 1b 57 81 f4',
        'in' => 'bc 42 39 73',
        'out' => '18 66 30 10 9e cd ec 4c a6 24 57 ba a8 dc 21 c9',
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,   15-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '8e 15 5b b6 24 2a 0c ba 63 42 a7 cb 14 8f e7 3b ab 28 48 eb ce a6 35 d6',
        'iv' => 'be 3e 3d 80 ec a1 ce 92 c3 c3 17 2e 46 68 81 4a',
        'in' => '08 b1 80 6d b1 1e cc 09 9a f4 9f 0d ff 72 cc',
        'out' => 'ee 41 b3 0b 32 40 44 64 40 71 57 61 14 3b 79 3b',
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,   15-byte input,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '6d e4 7b fe 4e 77 c4 f6 89 dc f3 29 d3 87 e6 d0 a8 36 db cf bd 3d 25 56',
        'iv' => '1e 4e e9 16 6f 31 d7 ca',
        'in' => '0e 46 a7 a4 a5 90 82 f3 bf b2 d1 6c 87 a8 7a',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,  255-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '8b fd 25 5f 48 2a 0f e9 75 11 3a 0a a2 5d e1 e5 e6 18 e7 db 88 ac 92 15',
        'in' => '38 e8 f3 28 3f 42 b5 39 64 13 55 5f 3a da 2d fb d7 90 cc 26 e6 9f f4 09 12 21 10 e3 ae ce 14 9c a2 cc 64 33 68 69 6b 4a ae 07 0d 77 d3 1d 37 6e 49 34 6d 70 b7 49 d8 55 5b 86 4b d2 12 ac 9a e8 9a 07 c1 b3 3b 97 57 e2 7a e5 6e 6c c1 76 37 bb 28 77 72 55 75 52 a3 df 8b 6a 33 9f ab a4 f3 d3 7b 9b 99 6e 42 a5 4f e7 9a 37 14 6d c2 19 e4 57 55 a2 bc 04 1e d3 22 06 fb 46 f1 a3 f0 c7 f6 a6 97 98 e8 84 49 2f 0a 32 a5 c8 92 0f af 50 d7 e7 0d 1f df 6d 6a 08 74 23 6c 3e 84 53 0f 59 05 a7 37 94 39 80 5e 17 ca 90 bc 07 7e 02 46 86 8c dc 76 ce ca a4 63 55 a6 c3 31 90 95 2d eb fb e8 7d d5 74 49 64 4b 8e 2e ee 54 87 8c e9 98 43 87 a8 b0 cc 35 a4 db b3 6d 59 9b c6 c7 cb 5c dd 95 ae 9d aa 4d c9 3c 77 1f 89 84 b8 09 72 51 7a 66 c9 63 5b d6 d8 6e d0 91 6e fa 17 1b c6 19 b5 d6',
        'out' => 'e9 8e 6c 36 2f 5d 45 29 29 0a ff 9f 8d 0e 77 13 d0 41 63 91 b8 07 7f a5 6d 9d be 73 0d 86 45 77 75 28 89 58 5d 6a 17 52 e4 ea 84 b2 99 ec c7 b7 01 63 b7 c9 85 2c 65 35 ea bd 09 16 22 07 e4 39 0e d1 e8 9f fe 08 21 17 85 9b b8 73 38 db 95 4b 28 6c 4d 9a b0 99 4a c2 cf 80 ca c0 7f 44 12 2d 48 0e f7 93 45 88 62 1f 25 70 98 94 2e f1 23 a9 5b 5f 3e a3 17 15 38 3e 65 f8 8b 6a 8b 5f a0 15 dd a0 76 49 dd ca fd f0 53 e7 63 97 6e 0c 5b ef 77 a2 33 59 aa 7a d5 7e 26 d8 5d b9 5d 7c 77 b5 b3 62 41 58 73 33 94 3b f8 cc 1d 26 96 fa 46 81 0d f0 b1 cb 57 69 62 80 73 30 f5 b4 08 49 b9 ec d8 bc dc 7b 3e 64 37 d2 e6 ad 6e ea 22 b7 ca 68 6c c6 18 bb 17 23 0a 45 97 a6 0c 23 4e 26 d3 e7 b5 58 d6 33 6d 6e f6 92 f4 27 3b 95 01 b9 0b f3 47 dd de e5 df 14 31 25 b9 02 ae ef 76 58 21 17',
      ]],
      'aes-192-cbc,    no padding, 24-byte key,  256-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '4a 49 6d 02 ae 74 6e 1d 8c db e5 51 03 ab ba c8 1e 79 39 ee 6d e5 43 27',
        'iv' => '4a 1c e3 f9 0e d8 25 4c 4c 9b 42 67 c8 a5 d8 9f',
        'in' => 'c6 e0 03 09 d9 82 2c ff 85 15 2f 1a 39 54 56 1e 05 a8 1b 5c d8 97 1e 86 31 27 17 ae 94 e9 6f 56 0c 12 f3 76 a6 22 f0 0d d5 ee 79 22 99 b3 93 31 78 1b f2 85 7b 32 69 30 54 21 9e b4 b2 ec cf 70 c6 00 3b 49 3e 9f 5f 45 42 61 9b 48 58 21 5f e5 e0 2a 57 84 f3 1a 75 f9 cc f0 54 32 c2 2c 85 4a c3 5e 39 5c 1c 95 e1 51 97 3a a9 f0 60 ce 42 1c 1a b3 ef 18 1b 48 7f 8e e1 3a 7c f0 91 70 1e 0e 73 b5 35 1e 78 3d db ee 60 4b 33 1f 46 a8 fe fe 30 8a c1 40 16 af 4b 4a 60 b2 d2 01 5b 77 e6 85 b7 6c 9b f1 d8 b6 0b e9 05 2f 9b 47 d5 c9 c7 41 c2 e2 84 a0 55 2f 38 98 5f 9f 7d 8a 10 7f 19 c5 34 bb 39 19 a0 f8 f1 d4 fd 2f 10 8a d3 6c 57 9b 95 70 4c ab 4b 9a 09 28 30 6f ff 02 5a f6 7d 3e 59 a3 f7 07 2c 9b 96 d4 94 59 69 11 f5 01 04 ce 50 fe 19 a3 3b 09 b0 9e 66 f5 c3 40 90 4f b6 87',
        'out' => '1a db 2c a8 fc 42 55 61 aa 76 6b cd 20 f7 fb 9f dd a8 49 ff 17 72 a1 33 58 7f b2 0d 90 a2 eb 57 b2 81 7a 8f b2 92 31 3d 93 62 67 35 e4 c1 6c 14 70 dc ad c3 27 49 d8 49 3f 27 30 96 d6 4e 6f 77 31 7e af 7c 85 94 4e 61 66 e9 39 4c d8 85 fe 79 ef f5 92 52 6c b0 00 c2 ca 63 6b a6 b2 55 99 d5 22 20 d7 b2 c1 32 8d 50 e2 c6 d1 fd 32 24 73 06 f6 3a 49 b6 5b b5 8c dd 3f ca 99 1b 28 78 0d bc 15 80 2d f2 39 06 03 98 b3 1e 12 75 53 12 79 bb 0e ed 8b 41 28 3c c4 99 57 e9 49 25 14 d6 a3 99 3d 3d b0 88 32 94 36 10 88 c6 37 76 fe 60 43 c0 0a af 45 07 48 ba a8 32 08 7e 41 30 3a 71 a6 7d 23 da 2c 51 b6 4e a6 c0 0f ca db 4e e6 5b fc d6 9b 47 cf 18 16 cc af 66 5c 3a 08 44 d0 ae ed 6f f2 c3 a0 44 e5 e5 63 90 67 af 38 a2 2e f3 73 d6 c6 5c 26 57 5b 53 98 41 97 d6 06 af ce 11 28 56',
      ]],

      /* -------------------------------------------------- */

      'aes-256-cbc,    no padding, 32-byte key,   16-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'c8 83 9a ec 64 87 5a 87 97 99 92 ab 56 fa ef 89 f2 e7 f3 23 24 2c 30 7e 63 ab 4a ab bf ad 5a db',
        'in' => '06 89 86 ee 80 d0 3e c5 a6 1f 0b 44 06 29 b2 da',
        'out' => '65 ce 09 d7 51 58 8c b5 41 21 39 dd 90 30 83 e0',
      ]],
      'aes-256-cbc,    no padding, 32-byte key,   15-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => '1e 28 09 27 5f 86 96 5a 0d 74 54 f0 d6 2f f8 4d 53 d4 e3 28 c0 c7 04 2f ee 00 60 29 7f 76 62 08',
        'in' => '7f 38 42 c2 d0 da a8 0e a9 88 65 f2 fb 18 81',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidInputSizeException', 'input must be a multiple of 16 bytes'],
      ]],
      'aes-256-cbc,    no padding, 31-byte key,   16-byte input,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'a3 eb 53 c7 75 b7 31 e0 87 33 34 a6 80 72 a7 61 64 61 66 f2 61 cd 6b ec 51 9d 4e 8f 8e 5a b6',
        'in' => 'd8 57 59 20 d9 bc ba c0 b9 8f e8 88 b8 91 0c 41',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 32 bytes long'],
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,    4-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => 'ae c5 86 d4 0f c4 00 8b 73 ca ac 1d fe 1a 97 24 dd fe be cc 1e 66 1f 78 a8 f5 a6 4c e6 2f 06 d6',
        'in' => '0d e9 ab de',
        'out' => 'c7 03 29 0c c3 39 35 f3 1c 36 e3 f5 80 23 2c ab',
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,   15-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => '5e 63 49 96 05 de 63 3e 6c 68 8a 7e f5 4d 37 95 6b b3 48 ce cb cf e7 a5 44 53 3a e4 bb a9 8c de',
        'iv' => 'a8 a2 22 fa 5e 74 76 91 64 23 69 69 51 04 60 7d',
        'in' => 'd5 1a 71 4a 46 bd 27 f2 27 35 12 73 6a 25 3a',
        'out' => 'ec 80 c5 b1 d6 0b dd 14 d5 b5 1b f3 3c 86 98 98',
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,   15-byte input,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => '6e b3 a2 e9 e0 87 9a f4 84 82 82 0a ea 48 02 16 e2 fd b8 4b 8c 11 28 62 60 f3 13 c1 5a c6 25 5f',
        'iv' => 'fe d0 a2 86 46 56 e5 46',
        'in' => '6a b6 18 d8 2f 69 c5 8a 64 42 9b ef f4 37 7e',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,  255-byte input,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => 'f3 92 9b c3 13 2d 14 c6 85 5b c4 04 f9 c1 da c8 db 0e 33 2b 4f d3 b9 cf 5f 78 73 84 cc e4 55 e9',
        'in' => 'ea ec 89 01 76 72 3d 06 43 22 a9 a6 13 0d b5 2d b6 1c aa 36 7c df 6e e8 07 29 33 98 89 9a 5f 9e 22 e9 ac 59 49 30 f7 88 34 3f a8 88 b8 0f b5 d6 8b 0b b2 cb bd ba 59 57 a3 06 25 82 c9 7a 56 ae ad 1f 29 e2 90 98 f3 81 2b ef 4c 80 7e 5f 8b ee d0 da 97 7a 5f 59 58 63 ad ad bd 47 81 e9 86 c0 3c a1 c1 43 ef a0 3a 5e e4 bd 22 2f c5 8f 9e 10 ce fb 24 36 98 c9 6f 76 9b 5c 26 da 95 28 4d 58 06 82 11 d5 95 53 5a 9b fd ba 5a bc a8 bf 88 ef 8e fa f0 d5 00 ea 9b 01 87 87 e9 cf 2e 4a a1 ea 61 3e b0 a1 79 9a a9 34 0d a4 cb 98 13 0f 00 49 ba 45 03 f4 02 d4 f5 90 5d b0 28 b2 27 4f 51 8c f2 aa 47 2b 8b 33 9a ea 38 49 f4 9b 78 76 81 ac 8b 06 da 5b 3b d1 0c 85 e9 71 53 81 81 d9 f3 bb e1 c1 a9 c7 8d 0f 77 83 a9 4a ec 9b 9f 0f 95 48 65 b3 10 a9 c2 67 94 87 51 7c 69 e6 db 13 c2',
        'out' => '36 54 94 e4 b8 c1 bc b5 29 ff 1b 72 83 8e 47 00 4e b3 9d 17 4f b4 8d 03 f7 c4 29 50 90 44 4e 88 49 d2 fe fa 20 11 f1 c2 1e dc 8d 2e 0f 22 b0 41 da 87 82 66 c4 43 f3 ab 77 dc 93 b3 e9 72 a4 15 4e b1 7a 5a 76 bc aa 37 34 05 07 08 61 98 94 59 48 92 7d 77 6b 4f 10 da 2d 11 96 7d eb 76 40 85 24 07 42 0a d3 8d 1b 36 be be 52 d3 d4 57 e5 1e f7 45 18 37 5e bb a6 02 6d da 81 13 31 8d 07 c0 54 0e 4e de 6b a4 82 3c 00 76 af 43 f8 12 be 00 c3 f3 a6 0b 95 c9 38 dd 20 42 72 82 21 5c 8a c4 1b b1 f4 5d 33 99 00 70 c7 5d 70 93 28 66 52 82 bf b5 19 6d c4 4f bf 8f 44 ca e2 1c 80 e7 c9 99 ba 98 1c ce 1c 64 16 8a d1 64 bb 6c e5 82 b2 47 23 a3 29 2d 6d 5d 2a 35 2a 98 a2 bf 30 85 9a b7 d3 9f af 4f dc 4b 3e 76 ba c3 bb 93 30 12 2c e0 ec 28 07 40 b0 29 39 95 32 a7 ad 9f 62 c5 ad b9',
      ]],
      'aes-256-cbc,    no padding, 32-byte key,  256-byte input,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'ec 69 b5 69 5f 9c c3 6a ec b6 10 71 ad 9b 19 21 87 93 a9 8e 0d b2 8d fa 6d a9 e4 56 60 5e 02 dc',
        'iv' => 'be fc 0b d5 41 ae 06 e5 38 38 bc cf fc ae 05 50',
        'in' => '8f 4d 50 63 f9 f2 5a b9 50 b1 8f 33 b6 d7 8a fc c9 0c 17 86 09 f1 5f d5 14 9a 75 23 8c e7 e1 9a 0e 10 6e b8 eb 58 0e 41 2a bf 30 2b 42 e4 f3 2f a7 c1 8f cd 2e 7b 79 63 66 0a 01 91 e1 66 8b 3e ed 52 d3 9e c3 aa d2 4b 6b c8 0c 40 cf 54 c6 72 e7 96 d4 a2 00 18 3d 75 81 fb 05 0e 3c eb 7a 8c a3 f8 3a a3 a6 df 09 c8 5c 33 00 d2 d2 2d 52 df 22 ab 04 d6 df 0c 78 c5 00 99 9b 6f 0f e0 eb 14 db fa 1a fb 04 ee 0e 86 a9 b2 86 4c f5 f3 5b 07 15 51 50 42 1b 9b df 6f 73 64 11 a1 46 01 dd cd 55 1f 4b 73 9f 3c fe 81 60 87 85 62 31 08 e2 88 e3 d4 6d f5 e9 38 da 78 eb 39 97 35 73 56 f8 99 39 a4 2a d9 ba e6 64 cf 7f 75 89 f5 77 51 4c f2 8f d0 88 d0 9a 7b 02 33 ae 73 db 68 6c fa 00 e0 8b 9b e7 f3 14 26 e5 1c 34 92 87 f0 5c 9c d4 35 d9 e1 4a df 5b 71 47 f3 63 a7 0b 56 8a a9 a0 0b',
        'out' => '66 21 3c 19 36 ab 8d 3f 0e d5 22 40 54 59 cd 75 62 e8 c1 c1 59 09 d1 4a 55 d7 4b e7 37 5b 27 95 c0 c8 10 ce 26 29 dd 74 a2 ab 53 3a cc 7b 54 fe 82 58 c9 3a e4 53 72 ad d5 ac 2d 2b 5a 68 c0 75 ae 1d 06 1e 5d 1f 78 88 68 5d 2b 31 95 ab af ed 31 62 40 09 c9 65 0a f6 8d a9 4a b2 f7 24 26 bd 7b d1 45 a0 5f 2b f9 92 0e 1b 72 b7 dd 85 60 55 d1 9d 86 c7 c7 80 cf d1 bc f3 41 31 79 08 81 0a 12 9b 43 91 5b 50 fd 15 fa 2f 1c 4d bc c0 bf 8b d8 09 96 8b ac 19 e2 8f 0c 25 b6 ff b2 4e 64 f3 1d 46 9c ac 9e c0 7f cf ba 4e f6 c3 3e 69 6c 8a 7c 6e 79 7e cb 96 ef 6f c2 b7 34 15 8b 5a b5 3f a5 e6 3a 1f 8b 7a 45 eb a0 c4 e7 56 6c 95 79 b7 05 1c fb 13 e9 bf 61 86 aa a8 25 eb 08 f6 79 30 f7 78 1a 8e 53 c9 ae 2d 16 31 80 d8 2b 86 87 fc 9e d6 fd a3 21 9a fb 70 92 2f 27 ae 23 86 c6 eb',
      ]],
    ];
  }

  #[DataProvider('encryptionProvider')]
  public function testEncryption(array $opts): void {
    if (!is_array($opts) || !isset($opts['mode']) || !isset($opts['key']) || !isset($opts['in'])) {
      throw new InvalidArgumentException('invalid encryption test case options');
    }

    $data = Hex::decode($opts['in']);
    $key = Hex::decode($opts['key']);
    $out = (isset($opts['out']) && is_string($opts['out']) ? Hex::decode($opts['out']) : '');
    $iv = (isset($opts['iv']) ? Hex::decode($opts['iv']) : '');

    $ex = (isset($opts['exception']) ? $opts['exception'] : null);
    if ($ex !== null && !is_array($ex)) {
      $ex = [$ex];
    }
    if (!empty($ex) && !is_string($ex[0])) {
      throw new TypeError(
        sprintf('test case exception class must be a string, %s given', gettype($ex[0])),
      );
    }

    if (!empty($ex)) {
      $this->expectException($ex[0]);

      if (count($ex) > 1) {
        if (is_integer($ex[1])) {
          $this->expectExceptionCode($ex[1]);
        } else if (is_string($ex[1])) {
          $this->expectExceptionMessage($ex[1]);
        }
      }
    }

    $enc = null;

    $bitsMode = ($opts['mode']&self::MODE_BITS_MASK);
    switch ($bitsMode) {
    case self::MODE_BITS_128:
      $enc = new AES\AES128($key, $iv);
      break;
    case self::MODE_BITS_192:
      $enc = new AES\AES192($key, $iv);
      break;
    case self::MODE_BITS_256:
      $enc = new AES\AES256($key, $iv);
      break;

    default:
      throw new InvalidArgumentException('unsupported encryption bit mode');
    }

    if (!($enc instanceof AES\AES)) {
      throw new RuntimeException('invalid cipher context object');
    }

    $padMode = ($opts['mode']&self::MODE_PADDING_MASK);
    switch ($padMode) {
    case self::MODE_PADDING_NONE:
      break;
    case self::MODE_PADDING_PKCS7:
      PKCS7::pad($data, $enc::getBlockLength());
      break;

    default:
      throw new InvalidArgumentException('unsupported encryption padding mode');
    }

    $controlData = '';

    $cipherMode = ($opts['mode']&self::MODE_CIPHER_MASK);
    switch ($cipherMode) {
    case self::MODE_CIPHER_CBC:
      $controlData = openssl_encrypt(
        $data,
        'aes-' . (strlen($key) * 8) . '-cbc',
        $key,
        OPENSSL_NO_PADDING,
        (!empty($iv) ? $iv : $enc::DEFAULT_IV),
      );

      $enc->encrypt($data, 'cbc');

      break;

    default:
      throw new InvalidArgumentException('unsupported encryption cipher mode');
    }

    if (is_string($out)) {
      $this->assertBinaryStringEquals($data, $out, 'Encrypted data does not equal the expected value.');
      if (!empty($controlData)) {
        $this->assertBinaryStringEquals($data, $controlData, 'Encrypted data does not equal the value returned by OpenSSL.');
      }
    }
  }

  public static function decryptionProvider(): array {
    return [
      'aes-128-cbc,    no padding, 16-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => '19 8d a6 61 d3 74 b8 a8 95 91 35 cd 8d e7 b6 32',
        'encrypted' => '0b 08 8f bf 5f ef 1c 5f 42 22 2d e8 a6 1d d7 46',
        'decrypted' => '10 4b cb d3 bc 20 c7 de 99 c1 5c 7a 50 39 8b 8b',
      ]],
      'aes-128-cbc,    no padding, 15-byte key,   16-byte ciphertext,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => '90 bc 8b ae da 30 c3 7a 4a 31 f8 c8 ea ee 50',
        'encrypted' => 'd7 9c fb 57 a7 0b 51 aa d5 e8 84 d3 c1 de f1 87',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 16 bytes long'],
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '53 95 8b 5f f9 47 07 4c eb d6 f5 e4 04 fd 39 8c',
        'encrypted' => 'f9 08 4f aa 8c 0b 61 2b 72 d0 19 12 b8 27 e8 2b',
        'decrypted' => '66 a9 7b 3e',
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,   16-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '58 83 bc a3 38 dc c4 a5 31 90 67 fb ce 4e e9 9b',
        'iv' => '20 d0 85 f0 05 c1 51 3e f3 39 2a a3 48 63 34 9f',
        'encrypted' => 'f1 7d 86 b0 5c e2 41 0b bc 6f be c0 49 c1 71 ab',
        'decrypted' => '0c 4a 32 ee 6f 2e 51 7c 7c 90 43 21 69 0d 9a',
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,   16-byte ciphertext,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '9a e5 e3 5c cd 85 d8 ab 19 cc 1f a9 62 93 1a 44',
        'iv' => '81 2b e4 8e 91 cf df aa',
        'encrypted' => '44 1f c5 6b d6 7e a5 ad 4e d0 ad 24 ca b5 d5 08',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-128-cbc, PKCS7 padding, 16-byte key,  256-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_PKCS7),
        'key' => '88 1c dc ae 8a b9 11 eb 94 3a 90 e3 5e 66 3a 01',
        'encrypted' => 'f6 88 0e 2f 9d f1 67 29 af e9 73 35 2f bd 04 98 79 07 c1 10 87 d2 27 0d 9c 68 9c c8 85 ea 63 26 4b fb a9 b5 a3 3f 62 e1 c6 19 dd a9 a2 81 69 33 ae 3d 9b e9 2b f9 0a 11 fe 9a c7 2b 20 c0 a3 2e 09 49 1d 9a d8 ce a8 89 81 7b dc 15 f5 5a 3c aa 63 ed d9 07 b9 7e 05 8b d0 1d e0 51 31 de 47 7c 51 b2 af 07 96 c2 78 40 77 28 fe 31 cb a3 3a 85 e6 6f 39 0e 1d 6f fc 3d 77 39 f7 4d 26 fc 7b 38 b3 57 c5 b2 42 11 a6 ee c4 ce b7 8b 71 c3 9a 86 10 9d 49 e6 19 d1 9e 71 cd 3f fa fd 6e 65 18 4e 1a c7 f0 b1 a6 6e 7e bf 51 51 e9 55 f3 3d 9a c6 fa 4f 00 3b 41 e8 b2 aa b0 3d d5 6b 89 b4 1d b6 1d a8 4c d4 3b 9a af 35 a1 19 04 74 6c 8b ad 11 47 f1 02 e5 34 cc ef 06 ac 78 12 d7 16 62 23 64 a3 b5 4c f7 b9 64 e2 4a 79 07 4b 60 3f 0b 81 7a 7d 41 62 00 80 7d 49 07 95 b7 1d ca 5a e3 94 4e',
        'decrypted' => '6f 7f 7f 42 a8 70 38 33 6d c9 bd 14 1b bf 67 ef b7 bb e3 01 07 76 13 8f a8 b2 db 30 4e a0 0f 6b fd d5 b7 e6 42 04 8a 04 17 fd 9b 99 0c 03 6b e2 9d 9a 50 9b 29 77 a4 ac 31 7d b5 95 41 a7 53 93 8c b6 6f de de 66 ca a6 68 19 6f 14 a0 8d 2d 5e e3 b8 d0 d1 ac 08 68 f5 9d aa 2c 09 a3 4e 4e 35 a8 6c 86 83 92 2b 84 a3 d3 0a bb 00 0b 5a e3 76 6a b2 e3 39 1f d0 ad ec fc ac b8 cd a1 0b 4c 7a aa 9c da 6c b2 37 57 5b 30 2a f9 4e ef fa 65 45 3b 79 1b ee ae 90 9a 20 d2 70 30 f8 87 2b ca 61 8d 7f e2 94 5a 67 d4 1f 32 f2 4c a7 a0 cb cf 44 76 2c ec b3 03 ad 60 43 93 6a ef f6 e5 e0 c3 83 3a a9 d6 5e 09 c4 c2 64 84 a6 f8 bf 0d ac 42 56 5e 8e d1 1b eb a3 6f 0d 2a 36 0d 33 01 59 d7 ec 75 d8 14 6e 8d 70 73 d7 15 05 78 55 43 9b f8 33 d6 30 e7 2a 01 b3 67 16 f7 21 a7 1e 66 00 8c',
      ]],
      'aes-128-cbc,    no padding, 16-byte key,  256-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_128 | self::MODE_PADDING_NONE),
        'key' => '98 66 8b c0 82 71 9c f5 a0 0f 4f 4f d7 58 4d f2',
        'iv' => 'b6 b9 d4 ce 6b b9 9b 16 8c 6b 1d da ca e0 17 61',
        'encrypted' => '59 b4 f8 86 fc bd 38 91 93 db 72 2c 1e 9d 9c 76 e5 f8 e4 21 e6 75 fa 4f e6 3a 28 31 f2 ca 3b 92 4c 05 62 55 43 1a 92 18 37 48 42 d1 8a e4 e3 5b ec dd 0b 13 20 0f 13 35 c5 97 e7 ac 88 bd fb ba df 32 57 4a 9c aa ce 5f eb 3e 82 46 70 0a c2 f3 bd ea b7 cb b9 e5 43 1a fb c8 5a 06 1f cf f4 f6 0e 67 a8 f7 ec 9c 70 d7 f3 c7 3a ad 55 90 ab 1f fd 65 f2 f7 ce 3f 99 9d 33 57 2f ff a6 7e 3e a2 a5 e5 1a eb 0e e3 89 7f dd fc 59 85 eb e6 f3 fd e9 83 5a ad 5f 2b 3e cf b1 57 bd fc 35 74 7b 07 17 46 8b 20 fb 2a 2e 09 b3 72 7a d2 28 36 8b ee c1 ee ce 90 65 ba af 8e 64 23 50 4b 17 ca 08 13 df 1a 3d 4c dd 74 39 ae 48 a2 a6 1c 03 87 aa 3b ac 56 4b 31 53 d4 00 b0 8a 0d 61 bb 02 5c 8d 47 36 db a7 18 1e e0 00 97 ba 7c 5c 8e d3 30 3e 9f d2 3e 00 d9 42 55 c4 50 c9 ee 47 4d 62 05 36 45',
        'decrypted' => '23 c0 44 33 78 9b ed ba 3d cc 98 cc c0 5a db 7e e0 f7 b0 12 66 6d 45 fe 5b f7 05 c5 81 eb 4b 47 b4 6e 02 08 80 d6 62 ee 71 02 6b 72 e7 f4 9a f8 1c 4a 23 e7 45 84 f7 65 64 2d 11 2e 8a c4 e1 f7 1a 47 89 33 4a 71 d4 15 26 71 e9 01 39 ad 86 24 2e 4a d2 88 6d 49 24 c0 e9 8b 5e 80 52 bb 4d ea 84 01 91 b9 42 4c d6 a2 c4 af 92 81 42 27 29 f7 27 8a c7 80 06 fc a2 da 04 17 f1 fd 99 a9 84 15 fe 72 2a 29 e6 d4 d9 2f bf 1d 4a f9 81 ad 94 45 fd b7 2b 97 70 86 cc 2a e1 4f 87 31 49 29 46 c7 f4 7f 8b 94 42 00 e8 e8 53 ae 76 85 a5 14 01 03 47 9b c3 08 6c a9 f9 e5 c9 8c 3f 2b 93 16 96 54 44 6f 1b 10 03 78 a6 f8 ad 81 98 1d 53 31 ed b7 23 17 3e 83 3b 2b 94 a9 39 bf 75 c9 34 aa 87 6a 77 c0 ee 1c dc a2 d9 6a d3 ae 39 df 5c b2 a3 af a6 95 21 0f 46 4c 2d 50 63 c8 4c c0 1b f7 3b 92',
      ]],

      /* -------------------------------------------------- */

      'aes-192-cbc,    no padding, 24-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '53 26 0f ff ae 5f b0 a9 75 85 b3 e5 2f 85 6c c5 5f 09 6b bc fb 60 5c 19',
        'encrypted' => 'd4 12 3a ef 24 70 f6 a7 96 89 21 2b ed b0 59 52',
        'decrypted' => '20 fe 9f fc ca cb 42 e1 59 fd fc cf c0 15 af 35',
      ]],
      'aes-192-cbc,    no padding, 23-byte key,   16-byte ciphertext,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '38 e5 62 c1 4f 60 0d 00 5d f6 d0 1a 47 bd e8 e5 25 98 17 4b f0 1e fa',
        'encrypted' => '03 f1 53 8c 4a de f0 fb fb 4b 41 40 ee dd b1 ea',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 24 bytes long'],
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '61 e1 25 c9 5c a1 d0 b9 61 1d a8 2b f2 80 c9 57 4a 5b 5c 4f e9 07 0f bf',
        'encrypted' => 'd7 97 88 f9 49 99 9c 34 7f 29 71 b2 81 20 60 bf',
        'decrypted' => 'd8 2d 44 25',
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,   16-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => 'b0 c1 d7 db a8 62 f8 88 ec f5 e8 cc a4 96 f0 a2 3c ec c9 b9 99 b9 64 b6',
        'iv' => 'd9 03 f4 f6 76 64 0b a6 f4 3b 45 89 8c b8 2d bc',
        'encrypted' => 'ad 9b 13 9d 3b 1c 64 a0 4e 5c eb b7 96 48 81 c1',
        'decrypted' => '77 7a 8f af af ca c2 74 75 a2 ce 62 2d c3 53',
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,   16-byte ciphertext,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '04 0d a2 b9 f8 e2 8c ae b1 18 7b 15 58 2f c8 60 d0 63 c2 bd 2d bc db 5d',
        'iv' => '27 85 57 81 28 0a 73 42',
        'encrypted' => '21 58 96 6a a6 98 64 6e 64 d1 09 aa 6e 84 57 d8',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-192-cbc, PKCS7 padding, 24-byte key,  256-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_PKCS7),
        'key' => '4d 7c ec 73 49 e1 10 f6 71 03 f8 70 79 3b 0e 9d f0 99 87 5c c9 76 75 21',
        'encrypted' => 'bd a9 bb 96 ab 7a 8d 4c 71 d5 a8 a8 1a 53 3c 03 4c 80 78 e7 29 7c 01 98 9e e5 7f d4 5f 25 12 2e 76 2c eb 93 26 77 37 b8 d2 b4 e1 cf 98 45 a2 14 3a d1 2c e9 5c 76 fa 86 0e 98 15 dd 24 1d 9b 78 07 68 c7 b7 df 72 81 02 f6 86 32 27 66 90 59 18 55 f9 81 89 4b 96 ad 1c 8b 15 f8 27 a1 ff 73 a1 87 26 9c ab 30 7a 47 ac da 59 e5 4b f1 46 bb f1 58 37 cf 92 32 39 4c 07 53 4c 64 57 12 b2 aa a6 a3 85 7b b6 88 75 32 c9 0b 97 84 d4 aa 0f 14 1e da 72 71 ea 97 fa e6 34 80 15 b4 2e 60 7a f5 63 4e 32 8b 09 28 3b aa 02 16 d1 06 38 56 d9 b3 de f5 d5 5a 2b 4b 51 53 e7 39 50 c5 46 6c b3 2a 5f cb 5e 9c 45 9c 46 ae ce 59 bb 9f 4f a0 29 07 78 d8 f8 0e ff b3 26 5e 4e 31 2a 89 0d 38 c5 04 30 60 9f d2 f3 90 a5 df b1 a8 a3 ee 1c f7 0a 1b e0 51 dc b2 b3 e5 34 2c 82 fd 23 69 14 b5 f3 85 cc',
        'decrypted' => '82 43 70 2a ac b5 24 8b 54 66 a6 c7 05 18 e8 01 d1 7f 44 c3 78 eb ec aa 14 69 ab 75 7e 08 18 05 5e ee 5c 69 6a 6e e7 e1 73 17 c9 ca 6e 06 b9 f2 c5 63 9e fb 66 d0 73 00 e5 36 73 1d f7 51 7b bf 41 8d f0 fa e6 85 10 63 fd a8 5c 12 e7 cf f5 a5 9d a8 61 f6 96 c5 47 3a 0c ce c9 8c d4 4d 83 82 2d 9c c4 1d 55 2b 2b 36 25 b5 19 4d a0 a0 60 be 10 c8 d2 92 40 a6 13 58 91 8f 08 90 59 78 69 c5 d8 57 7d a6 50 3f 2f 59 93 af 62 fd 0a bb b5 37 30 a8 3a e3 94 ed d4 a8 58 cf f8 ea 84 13 8e b2 f8 2b fc 66 31 66 cd 0e 3b d4 ba dc dd 88 ae bb 38 7a 3a 65 45 01 d9 61 88 58 a3 70 95 d7 a2 5d 86 29 22 cd 99 03 d4 00 af 6a b2 80 52 af ca 5b 8a 34 6a 75 27 a1 29 3a 43 3f 43 30 3b 12 ce 59 ef 9a b4 d6 cf fc 32 5e 7f 87 5b e4 5d 87 0c ef 6a 70 7c 69 ac 4d 3e 88 b7 42 4f 58 d6 1d 93',
      ]],
      'aes-192-cbc,    no padding, 24-byte key,  256-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_192 | self::MODE_PADDING_NONE),
        'key' => '73 a7 89 7c ae 34 dc 09 b0 ba d5 7a 7d 9f c9 bd 92 53 ac 19 e7 de 53 bc',
        'iv' => '63 03 d5 2c e6 b6 79 7b 25 a6 60 80 18 4a 42 ad',
        'encrypted' => 'cf fb ab 19 f8 b9 68 dc 22 e5 cf 3c 5d 76 34 f5 3c 26 25 8d 96 72 45 0e 3a 53 5d f2 c6 7c ac 95 91 e5 21 92 0e 43 35 71 ef b7 23 9e 6b 3e f7 b9 5c f9 bd 04 9e 0a d7 f4 7d d6 37 7b 6b 68 a5 aa 95 9a 14 20 cf 96 48 3e 3d 36 b1 85 8a ff 99 1e 4e ee 97 3d 8a 0d 1a e8 a4 5e 98 81 b8 25 f9 c7 8a b4 fb 10 9e 16 cb d3 4c f4 ca 3b 16 f1 62 5d a5 69 de c7 30 ea 40 66 16 cf 19 68 67 5c b1 81 a9 3f ae a6 a3 e8 d5 18 b0 03 b4 1c 84 a6 26 3a 39 d2 9f fb d5 7c a9 ec ff 7f f9 5f d0 b3 80 4c 37 00 e8 9e 60 bf 1d 11 68 bd 41 ea b8 c0 0e b9 ae 53 43 36 d2 8d 7a 3b 91 09 46 6d 4b f2 4c 8b 10 96 a9 77 f8 93 bc e9 e0 ee 10 b4 9a ab a0 7c 27 d9 4a 4e eb 75 18 3e b3 0d 2e 88 91 68 24 3f fc 74 8c 7d 47 5e 11 99 af b5 0a 8e 00 46 1e a0 fb 8a 70 52 79 3a 39 d5 79 1b 21 af f6 b2 f1 86',
        'decrypted' => '6c b9 93 0c b1 6e ab 05 db e9 bf d5 f7 e0 35 8c 08 56 a7 c9 da 4e 5a 26 82 8e dc a0 83 e3 de 94 53 8f ff 11 7e 7e 8c ad 0d a6 28 70 29 52 e3 69 1f 54 10 a8 f1 3c 79 94 eb 83 b7 0b 6d bc 93 6e 8d f1 16 e8 0f bf ab 92 8b aa 47 ce ce 10 3e 44 3a 0d 02 8e 24 65 a8 36 13 e9 30 fd e4 7e 45 8f 1a 62 3b 29 d0 ed 7e c3 9a 48 3a 73 a4 26 bf 2d 70 55 cd 8b 43 34 0b 67 11 1c 37 c8 56 bc 96 95 52 4a 3c 97 9e 64 de 65 a4 98 18 e0 c5 b8 b3 4d f5 b0 2e dd dd 15 61 e2 ad 6b c7 ef 54 ef 80 7c 51 32 b9 43 dc 0f 51 2d 44 97 c1 9a 6a 11 91 6d 57 75 a4 61 cd cb 4b 84 3d f3 f5 de 8a 70 a8 5d f7 72 f3 1e 90 cf 2f 9a 5e e6 cb 66 ad b8 4b 0b db 9c c2 d0 f3 b5 0c d0 39 10 a9 24 5b e7 36 ab ea 8e 0c a2 5a 43 1a f5 5a c3 26 1a e9 f2 a6 58 9f bd 0f f5 b0 65 db f5 e3 ff 83 82 ae c2 14 be',
      ]],

      /* -------------------------------------------------- */

      'aes-256-cbc,    no padding, 32-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'ac 62 6d 0f a5 d6 00 23 bf 66 4b 68 21 f9 53 01 bd a7 2b 36 5c e4 68 6b 6b bc ca 3c 46 a8 88 f7',
        'encrypted' => '52 0f b6 49 eb 97 f5 2c fe bc f0 3d eb 38 35 c6',
        'decrypted' => '3f fd 7b c4 bf 33 eb 21 c7 6d f5 96 f3 a7 f0 a2',
      ]],
      'aes-256-cbc,    no padding, 31-byte key,   16-byte ciphertext,  default IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'f7 d8 0b 56 ea 92 0c 9c 54 89 07 a9 69 b0 4b 53 ca a1 5d de 0a 06 dc 5e dc 23 61 c4 38 eb bd',
        'encrypted' => '8d 7f 5f fb 37 0d a0 8e 2e 73 f4 0d fd 0f 67 ec',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidKeySizeException', 'key must be 32 bytes long'],
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,   16-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => '0e 1e bb 47 d2 71 a1 22 dd c2 45 c9 07 14 c1 ea e6 3f 8a b0 15 f5 26 4c 6b 7a be 26 90 c9 15 bb',
        'encrypted' => '3d 8f 22 62 b0 67 89 c5 c6 cc 99 f7 2a 23 fe 62',
        'decrypted' => '8a 04 a0 ea',
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,   16-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => '65 f0 c9 8e ae d1 cd f2 18 ba d4 46 71 e8 a0 5b 6c 8c be 4c 8e 23 8d d2 2f d0 b0 47 41 cd 00 fa',
        'iv' => '07 10 f2 85 44 2a 26 7e ec 53 f1 4d 58 86 2a b2',
        'encrypted' => '23 a3 6e 75 83 09 58 26 7a 55 f5 f8 da d7 11 bf',
        'decrypted' => 'ad e7 21 d9 7f 00 c2 86 56 03 64 44 15 10 48',
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,   16-byte ciphertext,   custom IV ---> exception' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => '38 d1 25 90 e0 f5 7d a0 36 46 21 7f f0 e5 05 81 b3 0d 95 2f b9 d7 ee 33 40 cf 2d 03 b3 37 d5 da',
        'iv' => 'f6 37 fb b1 d4 57 7f cb',
        'encrypted' => '9b 90 4a 69 3c 7c b1 f9 df 20 36 aa a9 00 ef 55',
        'exception' => ['CrudeCrypto\AES\Exceptions\InvalidIVSizeException', 'iv must be 16 bytes long'],
      ]],
      'aes-256-cbc, PKCS7 padding, 32-byte key,  256-byte ciphertext,  default IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_PKCS7),
        'key' => 'ca 77 fe c5 93 6d 35 f1 e4 05 4f e6 7d 9b 8d 29 08 9f 47 58 dd 3e 08 88 c7 d1 10 47 60 c2 60 29',
        'encrypted' => '41 4c af 15 d8 7f ce eb cf 8f 4e d0 05 23 ad 41 5c 7d 57 f5 9d 81 43 ca 9f 0c d8 a3 3b 94 1f 08 66 18 b4 2d 44 89 80 b3 00 23 cb 3d 9f 98 0e 37 ad 94 1c a8 56 9e 13 d7 a2 f3 1a 1b 31 ec 3a f2 44 20 89 75 96 53 03 36 cc 1b bc 49 81 41 e9 d5 e0 d6 d3 69 e6 fb 70 1a 6a b9 61 3f 29 1b eb 5e b4 f2 f6 ef 55 23 af e4 85 a8 64 01 62 16 9c 6b fd 56 dc ef 0e 30 7d 76 fb 87 1b eb d5 2e c4 05 a4 7c 8a 0f 3c e0 6e 00 91 a0 69 13 67 2b 2c 7b c3 41 93 99 32 e8 cd ca 7d cd dc 44 5d 93 6e 91 c5 91 11 d9 1a fb ce b2 9c e6 1a 37 c1 49 ed e8 63 79 e0 04 46 dd 3b e3 a8 e9 b6 45 11 93 c1 83 96 d1 d3 cb cc 00 b0 f8 2a 74 f7 f5 2a 5c ad 52 0e 8d f0 88 ea 8d 4e dc 63 ff 40 ac b1 f7 90 49 1e 58 71 70 0d fa 99 0f 8b ae 0f 43 a6 b4 91 78 68 e5 de 34 d3 f8 7b 61 94 68 63 8e d3 f9 78 38',
        'decrypted' => 'f7 02 4a 26 68 83 51 da a8 d9 7d 90 bd f6 aa 85 a3 a1 44 33 b0 ae 38 a5 48 88 19 08 15 0c 6a 9e 94 8e 7a 0f b1 a3 1b 70 e9 f7 1a 5a 64 7e 06 98 a1 7e 42 c0 fa a3 2d 2e 3e 8d e7 62 26 77 49 34 12 96 71 f4 73 fe 00 54 c9 9f 82 7f ed 69 01 d1 d5 dd 93 8c 5c ad 5c a2 ad f5 1e a3 c7 e3 b9 8c 62 8a 3e fe 55 06 d2 ce 9a 09 97 17 32 a7 fe 9a 3b 8a 9e 91 bc 58 09 2a 75 28 0f 01 83 9f fb 41 ec 89 23 d0 df 5a d4 22 28 99 33 0f be 7c f8 40 98 13 dd 14 52 10 47 74 18 ef 50 2c aa c1 5e 03 49 ed 97 db 66 06 79 b7 fb 55 e3 6a 63 d1 4a ad eb 06 f5 76 b5 92 0c b6 76 4e 75 03 79 ed 4c 17 5f 23 a2 8a a8 be db 07 7d f6 c2 3f c9 2d 0f bc b1 e6 7a 8f 14 18 6e 33 3d c4 9a 4a 3c 1f 55 ab 8c fe a8 54 cf f7 db 20 83 6e 79 6f a5 56 76 c3 66 4d 9f 9e 93 f8 cf 5d a8 85 ae 2c 76 24 a5',
      ]],
      'aes-256-cbc,    no padding, 32-byte key,  256-byte ciphertext,   custom IV ---> success' => [[
        'mode' => (self::MODE_CIPHER_CBC | self::MODE_BITS_256 | self::MODE_PADDING_NONE),
        'key' => 'b5 ac 4f 5d cc a9 28 78 b0 28 a7 2c 7c 60 a5 df 49 27 83 5b 32 8e e7 b0 0b 4d 9d 96 5a 87 a8 ad',
        'iv' => '9d a1 d6 c4 24 5e 78 f6 f0 07 51 41 96 74 07 be',
        'encrypted' => '7c 65 8b 55 70 55 15 17 ef e3 a7 7a a5 bc 0a 5e 3b 2e 4b 91 49 e4 1c 68 2d 83 91 3d d8 a4 79 68 c9 00 93 5c 09 73 67 4b 6a 13 42 86 64 3b af 2f b3 26 65 48 f6 7c 69 fc 85 4d ca 26 01 c2 5f 12 d9 30 f3 0b 60 dc b9 da b3 f5 da b9 48 74 f2 6b 75 2a 3e 40 2b d5 fe 27 05 94 68 cc cf ad cb 21 00 6a 6a 97 ed e7 38 54 bc 04 83 38 21 15 e3 2f a2 5f 71 57 3f a5 d0 30 1b a9 da 75 27 ef 8c f2 6d e9 bc a2 e2 4b d1 b2 fa b6 fb 44 3c be c4 88 81 48 93 dd 2f 30 8f 4f de b1 79 6f 35 04 08 a6 a1 e5 b1 c1 31 be b8 8d e0 a1 d2 9e 43 a0 e7 00 5e 1c 71 19 16 1a 6f 77 c5 e5 1d be 14 16 30 e4 d6 a8 65 da b9 c6 c8 b0 35 60 68 d3 a7 cd 93 da 35 6d 50 c9 52 1a c3 42 e8 7b 0b 52 c8 1b c9 08 76 a1 cc 81 cc 6a af 3f ca a1 48 04 78 c9 bc 32 6c e1 a2 6a 66 62 2b 1e 7b 5a 81 bc a3 a1 a1 16',
        'decrypted' => '5f ae a2 e9 c3 49 5f 35 8d a1 2a f9 91 6e 02 73 30 78 44 f5 de b5 3d d0 94 24 95 64 9e 0c 42 5e c7 6e 28 9e 77 00 90 13 3a 7f 42 b4 5d f4 59 04 14 10 1f f0 29 eb dc 10 19 a4 2a 31 79 a7 af f3 af fc 78 5d a9 22 5d 49 c2 95 f2 a3 a5 fb 15 b1 0e b0 2b e7 93 8f e7 fd 8f 70 0b c2 bd 8c c3 29 c1 19 c8 e3 2c 93 24 07 31 11 2a fb fe 7b 7a 15 6b fb 97 f8 ed 3c c9 0c 38 1b ae 99 17 d5 28 17 94 95 b7 25 70 7e 3c d8 7c 58 b1 a7 5f 77 32 64 51 0e 54 37 73 41 79 62 0a 72 bf 66 fd e3 53 e6 75 41 13 2c 6f 72 26 84 ac 34 d0 ba 13 ce 4c fd 60 f2 4a 24 5e 12 b2 65 c3 c4 7c cc 47 89 d9 e9 c8 eb c0 b8 a0 d3 fe 09 85 c9 98 db 9a da 82 df 27 53 bf fd 6a bc 1e 7a 89 21 2c 0d 4d ec f3 89 d0 9b a6 95 a0 94 84 74 ad b4 77 50 21 b4 97 a8 35 82 56 59 50 e2 cd d6 c9 65 d7 3f 5a 84 c2 1d',
      ]],
    ];
  }

  #[DataProvider('decryptionProvider')]
  public function testDecryption(array $opts): void {
    if (!is_array($opts) || !isset($opts['mode']) || !isset($opts['key']) || !isset($opts['encrypted'])) {
      throw new InvalidArgumentException('invalid decryption test case options');
    }

    $data = Hex::decode($opts['encrypted']);
    $key = Hex::decode($opts['key']);
    $decrypted = (isset($opts['decrypted']) && is_string($opts['decrypted']) ? Hex::decode($opts['decrypted']) : '');
    $iv = (isset($opts['iv']) ? Hex::decode($opts['iv']) : '');

    $ex = (isset($opts['exception']) ? $opts['exception'] : null);
    if ($ex !== null && !is_array($ex)) {
      $ex = [$ex];
    }
    if (!empty($ex) && !is_string($ex[0])) {
      throw new TypeError(
        sprintf('test case exception class must be a string, %s given', gettype($ex[0])),
      );
    }

    if (!empty($ex)) {
      $this->expectException($ex[0]);

      if (count($ex) > 1) {
        if (is_integer($ex[1])) {
          $this->expectExceptionCode($ex[1]);
        } else if (is_string($ex[1])) {
          $this->expectExceptionMessage($ex[1]);
        }
      }
    }

    $dec = null;

    $bitsMode = ($opts['mode']&self::MODE_BITS_MASK);
    switch ($bitsMode) {
    case self::MODE_BITS_128:
      $dec = new AES\AES128($key, $iv);
      break;
    case self::MODE_BITS_192:
      $dec = new AES\AES192($key, $iv);
      break;
    case self::MODE_BITS_256:
      $dec = new AES\AES256($key, $iv);
      break;

    default:
      throw new InvalidArgumentException('unsupported decryption bit mode');
    }

    if (!($dec instanceof AES\AES)) {
      throw new RuntimeException('invalid cipher context object');
    }

    $controlData = '';

    $cipherMode = ($opts['mode']&self::MODE_CIPHER_MASK);
    switch ($cipherMode) {
    case self::MODE_CIPHER_CBC:
      $controlData = openssl_decrypt(
        $data,
        'aes-' . (strlen($key) * 8) . '-cbc',
        $key,
        OPENSSL_NO_PADDING,
        (!empty($iv) ? $iv : $dec::DEFAULT_IV),
      );

      $dec->decrypt($data, 'cbc');
      break;

    default:
      throw new InvalidArgumentException('unsupported decryption cipher mode');
    }

    $padMode = ($opts['mode']&self::MODE_PADDING_MASK);
    switch ($padMode) {
    case self::MODE_PADDING_NONE:
      break;
    case self::MODE_PADDING_PKCS7:
      if (!empty($controlData)) {
        PKCS7::unpad($controlData, $dec::getBlockLength());
      }
      PKCS7::unpad($data, $dec::getBlockLength());
      break;

    default:
      throw new InvalidArgumentException('unsupported decryption padding mode');
    }

    if (is_string($decrypted)) {
      $this->assertBinaryStringEquals($data, $decrypted, 'Decrypted data does not equal the input used during encryption.');
      if (!empty($controlData)) {
        $this->assertBinaryStringEquals($data, $controlData, 'Decrypted data does not equal the value returned by OpenSSL.');
      }
    }
  }
}
