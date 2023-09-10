<?php declare (strict_types = 1);

namespace CrudeCrypto\Tests;

use CrudeCrypto\Hex;
use CrudeCrypto\PKCS7;
use CrudeCrypto\Tests\Assertions\BinaryStringAssertion;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PKCS7Test extends TestCase {
  use BinaryStringAssertion;

  public static function paddingProvider(): array {
    return [
      '1 byte(s) of padding' => [
        'unpadded' => '61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f',
        'padded' => '61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 01',
      ],
      '15 byte(s) of padding' => [
        'unpadded' => '',
        'padded' => '10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10',
      ],
    ];
  }

  public static function unpaddingProvider(): array {
    return [
      '1 byte(s) of padding' => [
        'padded' => '61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 01',
        'unpadded' => '61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f',
      ],
      '15 byte(s) of padding' => [
        'padded' => '10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10',
        'unpadded' => '',
      ],
    ];
  }

  #[DataProvider('paddingProvider')]
  public function testPad(string $unpadded, string $padded): void {
    $unpadded = Hex::decode($unpadded);
    $padded = Hex::decode($padded);

    PKCS7::pad($unpadded, 16);

    $this->assertBinaryStringEquals($unpadded, $padded);
  }

  #[DataProvider('unpaddingProvider')]
  public function testUnpad(string $padded, string $unpadded): void {
    $padded = Hex::decode($padded);
    $unpadded = Hex::decode($unpadded);

    PKCS7::unpad($padded, 16);

    $this->assertBinaryStringEquals($padded, $unpadded);
  }
}
