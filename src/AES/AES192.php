<?php

namespace CrudeCrypto\AES;

use CrudeCrypto\AES\AES;

class AES192 extends AES {
  protected static function getRoundNum() {return 12;}
  protected static function getKeyWordSize() {return 6;}
  protected static function getRoundKeySize() {return 208;}
}
