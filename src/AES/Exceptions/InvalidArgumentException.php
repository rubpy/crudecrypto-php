<?php

namespace CrudeCrypto\AES\Exceptions;

use CrudeCrypto\AES\Exceptions\Exception;

abstract class InvalidArgumentException extends Exception {
  public function __construct($message = '', $code = 0, $previous = null) {
    parent::__construct($message, $code, $previous);
  }
}
