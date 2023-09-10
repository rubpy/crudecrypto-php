<?php

namespace CrudeCrypto;

interface Cipher {
  public function getSupportedModes();

  public function encrypt(&$input, $mode);
  public function decrypt(&$input, $mode);
}
