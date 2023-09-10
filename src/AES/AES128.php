<?php

namespace CrudeCrypto\AES;

use CrudeCrypto\AES\AES;

class AES128 extends AES {
  protected static function getRoundNum() {return 10;}
  protected static function getKeyWordSize() {return 4;}
  protected static function getRoundKeySize() {return 176;}
}
