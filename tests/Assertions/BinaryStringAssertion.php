<?php declare (strict_types = 1);

namespace CrudeCrypto\Tests\Assertions;

use CrudeCrypto\Tests\Constraints\BinaryStringEqualsConstraint;
use function PHPUnit\Framework\assertThat;

trait BinaryStringAssertion {
  public static function assertBinaryStringEquals(string $expected, string $actual, string $message = ''): void {
    assertThat(
      $actual,
      new BinaryStringEqualsConstraint($expected),
      $message,
    );
  }
}
