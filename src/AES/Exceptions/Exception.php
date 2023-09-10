<?php

namespace CrudeCrypto\AES\Exceptions;

use RuntimeException;

class Exception extends RuntimeException {
  public function __construct($message = '', $code = 0, $previous = null) {
    parent::__construct($message, $code, $previous);
  }
}
