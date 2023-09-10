<?php

namespace CrudeCrypto;

interface Bufferable extends \ArrayAccess {
  public function adjust($size);
  public function length();
  public function &raw();
  public function index();
  public function insert($value, $index = 0);
  public function copy(&$dest, $n = -1, $index = 0, $pad = false, $destIndex = -1);
  public function append($value);
  public function get($n = 1, $index = 0, $pad = false);

  public function cursor($index);

  public function __toString();
}
