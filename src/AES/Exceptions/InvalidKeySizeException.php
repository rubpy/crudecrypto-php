<?php

namespace CrudeCrypto\AES\Exceptions;

use CrudeCrypto\AES\Exceptions\InvalidArgumentException;

class InvalidKeySizeException extends InvalidArgumentException {
  public function __construct($message = '', $code = 0, $previous = null) {
    parent::__construct($message, $code, $previous);
  }
}
