<?php declare (strict_types = 1);

namespace CrudeCrypto\Tests\Constraints;

use CrudeCrypto\Hex;
use PHPUnit\Framework\Constraint\Constraint;
use SebastianBergmann\Comparator\ComparisonFailure;

final class BinaryStringEqualsConstraint extends Constraint {
  private readonly mixed $value;

  public function __construct(mixed $value) {
    $this->value = $value;
  }

  public function evaluate(mixed $other, string $description = '', bool $returnResult = false): ?bool {
    $success = $this->value === $other;

    if ($returnResult) {
      return $success;
    }

    if (!$success) {
      $f = null;

      if (is_string($this->value) && is_string($other)) {
        $f = new ComparisonFailure(
          $this->value,
          $other,
          sprintf("[%s]", Hex::encode($this->value, Hex::ENCODE_SPACES)),
          sprintf("[%s]", Hex::encode($other, Hex::ENCODE_SPACES)),
        );
      }

      if (is_array($this->value) && is_array($other)) {
        $f = new ComparisonFailure(
          $this->value,
          $other,
          $this->exporter()->export($this->value),
          $this->exporter()->export($other),
        );
      }

      $this->fail($other, $description, $f);
    }

    return null;
  }

  public function toString(): string {
    if (is_object($this->value)) {
      return 'is identical to an object of class "' .
      $this->value::class . '"';
    }

    return 'is identical to ' . $this->exporter()->export($this->value);
  }

  protected function failureDescription(mixed $other): string {
    if (is_object($this->value) && is_object($other)) {
      return 'two variables reference the same object';
    }

    if (is_string($this->value) && is_string($other)) {
      return 'two strings are identical';
    }

    if (is_array($this->value) && is_array($other)) {
      return 'two arrays are identical';
    }

    return parent::failureDescription($other);
  }
}
