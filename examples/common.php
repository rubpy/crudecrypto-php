<?php

namespace {
  require dirname(__FILE__) . '/vendor/autoload.php';

  CrudeCrypto\Console::initialize();
}

// --------------------------------------------------

namespace CrudeCrypto {

  class Console {
    protected static $initialized = false;
    protected static $supportsColor = false;

    public static function initialize() {
      if (static::$initialized) {
        return;
      }

      static::$supportsColor = (DIRECTORY_SEPARATOR === '/');

      static::$initialized = true;
    }

    public static function sprint($msg = '', $color = 0) {
      $s = '';

      if (!self::$supportsColor) {
        $color = 0;
      }
      if ($color > 0) {
        $s .= "\033[" . strval($color) . 'm';
      }

      $s .= $msg;

      if ($color > 0) {
        $s .= "\033[0m";
      }

      return $s;
    }

    public static function println($msg = '', $color = 0) {
      echo self::sprint($msg . PHP_EOL, $color);
    }
  }

}
