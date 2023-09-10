<?php

namespace CrudeCrypto;

use CrudeCrypto\Buffer;
use CrudeCrypto\Bufferable;
use InvalidArgumentException;
use TypeError;

class PKCS7 {
  public static function pad(&$input, $blockLength) {
    if (!is_integer($blockLength)) {
      throw new TypeError(
        sprintf('blockLength must be an integer, %s given', gettype($blockLength)),
      );
    }
    if ($blockLength < 2 || $blockLength > PHP_INT_MAX) {
      throw new InvalidArgumentException('blockLength must be an integer in the range [2, ' . PHP_INT_MAX . ']');
    }

    $buffer = $input;
    if (!($input instanceof Bufferable)) {
      if (!is_string($buffer)) {
        throw new TypeError(
          sprintf('input must be a string or a ' . Bufferable::class . ', %s given', gettype($buffer)),
        );
      }

      $buffer = new Buffer(-1, $input);
    }

    $bufferLength = $buffer->length();

    $paddingLength = ($blockLength - ($bufferLength % $blockLength));
    $paddingValue = chr($paddingLength);
    $paddingData = str_repeat($paddingValue, $paddingLength);

    $buffer->append($paddingData);

    return $paddingLength;
  }

  public static function unpad(&$input, $blockLength) {
    if (!is_integer($blockLength)) {
      throw new TypeError(
        sprintf('blockLength must be an integer, %s given', gettype($blockLength)),
      );
    }
    if ($blockLength < 2 || $blockLength > PHP_INT_MAX) {
      throw new InvalidArgumentException('blockLength must be an integer in the range [2, ' . PHP_INT_MAX . ']');
    }

    $buffer = $input;
    if (!($input instanceof Bufferable)) {
      if (!is_string($buffer)) {
        throw new TypeError(
          sprintf('input must be a string or a ' . Bufferable::class . ', %s given', gettype($buffer)),
        );
      }

      $buffer = new Buffer(-1, $input);
    }

    $bufferLength = $buffer->length();
    if ($bufferLength < $blockLength) {
      return 0;
    }

    $paddingLength = $buffer[$bufferLength - 1];
    if ($paddingLength > $blockLength) {
      return 0;
    }

    $dataLength = ($bufferLength - $paddingLength);
    $buffer->adjust($dataLength);

    return $paddingLength;
  }
}
