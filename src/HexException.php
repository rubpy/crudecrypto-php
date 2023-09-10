<?php

namespace CrudeCrypto;

use RuntimeException;

class HexException extends RuntimeException {
  const ONLY_UPPERCASE = 1;
  const ONLY_LOWERCASE = 2;
  const ONLY_VALID_CHARSET = 3;
  const DISALLOWED_SPACE = 4;
  const DISALLOWED_NEWLINE = 5;
  const ODD_NIBBLE = 6;

  const CODE_MESSAGES = [
    self::ONLY_UPPERCASE => 'invalid hexadecimal string (only uppercase A-F digits allowed)',
    self::ONLY_LOWERCASE => 'invalid hexadecimal string (only lowercase A-F digits allowed)',
    self::ONLY_VALID_CHARSET => 'invalid hexadecimal string (only [a-zA-Z0-9] characters allowed)',
    self::DISALLOWED_SPACE => 'invalid hexadecimal string (space disallowed)',
    self::DISALLOWED_NEWLINE => 'invalid hexadecimal string (newline disallowed)',
    self::ODD_NIBBLE => 'invalid hexadecimal string (odd number of nibbles)',
  ];

  public function __construct($code = 0, $message = '', $previous = null) {
    if (empty($message)) {
      $message = self::getMessageFor($code);
    }

    parent::__construct($message, $code, $previous);
  }

  public static function getMessageFor($code) {
    if (isset(self::CODE_MESSAGES[$code])) {
      return self::CODE_MESSAGES[$code];
    }

    return 'unexpected error';
  }
}
