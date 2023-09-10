<?php

namespace CrudeCrypto\AES;

use CrudeCrypto\AES\AES;

class AES256 extends AES {
  protected static function getRoundNum() {return 14;}
  protected static function getKeyWordSize() {return 8;}
  protected static function getRoundKeySize() {return 240;}
}
