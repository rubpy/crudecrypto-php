<?php

namespace CrudeCrypto;

use CrudeCrypto\Buffer;
use CrudeCrypto\Bufferable;
use InvalidArgumentException;
use TypeError;

class BufferCursor implements Bufferable {
  protected Buffer $_buffer;
  protected $_index = 0;

  public function __construct(Buffer $buffer, $index = 0) {
    if ($buffer === null || !($buffer instanceof Buffer)) {
      throw new TypeError(
        sprintf('buffer must be an instance of ' . Buffer::class . ', %s given', gettype($buffer)),
      );
    }

    if (!is_integer($index)) {
      throw new TypeError(
        sprintf('index must be an integer, %s given', gettype($index)),
      );
    }
    if ($index < 0 || $index > PHP_INT_MAX) {
      throw new InvalidArgumentException('index must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $this->_buffer = $buffer;
    $this->_index = $index;
  }

  public function adjust($size) {
    $totalSize = $this->_index + $size;

    return $this->_buffer->adjust($totalSize);
  }

  public function length() {
    $len = $this->_buffer->length();
    if ($len <= $this->_index) {
      return 0;
    }

    return ($len - $this->_index);
  }

  public function &raw() {
    return $this->_buffer->raw();
  }

  public function cursor($index) {
    $pos = $this->_index + $index;

    return $this->_buffer->cursor($pos);
  }

  public function __toString() {
    return $this->_buffer->get(-1, $this->_index, false);
  }

  public function index() {
    return $this->_index;
  }

  public function insert($value, $index = 0) {
    return $this->_buffer->insert($value, ($this->_index + $index));
  }

  public function copy(&$dest, $n = -1, $index = 0, $pad = false, $destIndex = -1) {
    return $this->_buffer->copy($dest, $n, ($this->_index + $index), $pad, $destIndex);
  }

  public function append($value) {
    return $this->_buffer->append($value);
  }

  public function get($n = -1, $index = 0, $pad = false) {
    return $this->_buffer->get($n, ($this->_index + $index), $pad);
  }

  // --------------------------------------------------

  public function move($offset) {
    if (!is_integer($offset)) {
      throw new TypeError(
        sprintf('offset must be an integer, %s given', gettype($offset)),
      );
    }

    if ($offset === 0) {
      return $this->_index;
    }

    $index = max(0, ($this->_index + $offset));
    if ($index >= PHP_INT_MAX) {
      $index = (PHP_INT_MAX - 1);
    }

    $this->_index = $index;

    return $index;
  }

  // --------------------------------------------------

  #[\ReturnTypeWillChange]
  public function offsetExists($offset) {
    return $this->_buffer->offsetExists($this->_index + $offset);
  }

  #[\ReturnTypeWillChange]
  public function offsetGet($offset) {
    return $this->_buffer->offsetGet($this->_index + $offset);
  }

  #[\ReturnTypeWillChange]
  public function offsetSet($offset, $value) {
    return $this->_buffer->offsetSet(($this->_index + $offset), $value);
  }

  #[\ReturnTypeWillChange]
  public function offsetUnset($offset) {
    return $this->_buffer->offsetUnset($this->_index + $offset);
  }
}
