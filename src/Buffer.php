<?php

namespace CrudeCrypto;

use CrudeCrypto\Bufferable;
use InvalidArgumentException;
use TypeError;

class Buffer implements Bufferable {
  protected $_data = '';

  public function __construct($size = 0, &$data = null) {
    if (is_string($data)) {
      $this->_data =  &$data;
    }

    if (is_integer($size) && $size >= 0) {
      $this->adjust($size);
    }
  }

  public function adjust($size) {
    if (!is_integer($size)) {
      throw new TypeError(
        sprintf('size must be an integer, %s given', gettype($size)),
      );
    }
    if ($size < 0 || $size > PHP_INT_MAX) {
      throw new InvalidArgumentException('size must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $currSize = strlen($this->_data);
    if ($size === $currSize) {
      return $size;
    }

    if ($size === 0) {
      $this->_data = '';
    } else {
      if ($size < $currSize) {
        $this->_data = substr($this->_data, 0, $size);
      } else {
        $this->_data = str_pad($this->_data, $size, "\x00", STR_PAD_RIGHT);
      }
    }

    return $size;
  }

  public function length() {
    return strlen($this->_data);
  }

  public function &raw() {
    return $this->_data;
  }

  public function cursor($index) {
    return new BufferCursor($this, $index);
  }

  public function __toString() {
    return $this->_data;
  }

  public function index() {
    return (int) 0;
  }

  public function insert($value, $index = 0) {
    if (is_integer($value)) {
      $this->_data[0] = chr($value&0xff);
      return strlen($this->_data);
    } elseif (!is_string($value)) {
      throw new TypeError(
        sprintf('value must be an integer or a string, %s given', gettype($value)),
      );
    }

    $dataLength = strlen($this->_data);

    $valueLength = strlen($value);
    if ($valueLength === 0) {
      return $dataLength;
    }

    if (!is_integer($index)) {
      $index = (int) 0;
    } else {
      if ($index < 0) {
        throw new InvalidArgumentException('index must be a non-negative integer');
      } elseif ($index >= (PHP_INT_MAX - $dataLength)) {
        throw new InvalidArgumentException('index out of range');
      }
    }

    $totalLength = ($dataLength + $valueLength);
    $this->adjust($totalLength);

    for ($i = 0, $p = $index; $i < $valueLength; ++$i, ++$p) {
      $this->_data[$p] = $value[$i];
    }

    return strlen($this->_data);
  }

  public function copy(&$dest, $n = -1, $index = 0, $pad = false, $destIndex = -1) {
    $buffer = $dest;
    if (!($dest instanceof Bufferable)) {
      if (!is_string($dest)) {
        throw new TypeError(
          sprintf('dest must be a string or a ' . Bufferable::class . ', %s given', gettype($dest)),
        );
      }

      $buffer = new Buffer(-1, $dest);
    }

    if (!is_integer($n)) {
      throw new TypeError(
        sprintf('n must be an integer, %s given', gettype($n)),
      );
    }
    if ($n < -1 || $n >= PHP_INT_MAX) {
      throw new InvalidArgumentException('n must be an integer in the range [-1, ' . PHP_INT_MAX . ']');
    }

    if (!is_integer($index)) {
      throw new TypeError(
        sprintf('index must be an integer, %s given', gettype($index)),
      );
    }
    if ($index < 0 || $index >= PHP_INT_MAX) {
      throw new InvalidArgumentException('index must be a non-negative integer');
    }

    if (!is_integer($destIndex)) {
      throw new TypeError(
        sprintf('destIndex must be an integer, %s given', gettype($destIndex)),
      );
    }
    if ($destIndex < -1 || $destIndex >= PHP_INT_MAX) {
      throw new InvalidArgumentException('destIndex must be an integer in the range [-1, ' . PHP_INT_MAX . ']');
    }

    if ($n === 0) {
      return 0;
    }

    $len = strlen($this->_data);
    $left = ($index >= $len ? 0 : ($len - $index));
    $toCopy = ($n < 0 ? $left : min($n, $left));
    $destLen = $dest->length();

    $s = '';
    if ($toCopy > 0) {
      $s = substr($this->_data, $index, $toCopy);
    }
    if ($pad && $toCopy < $n) {
      $s = str_pad($s, $n, "\x00", STR_PAD_RIGHT);
    }

    if ($destIndex < 0) {
      $dest->append($s);
    } else {
      $dest->insert($s, $destIndex);
    }

    return $toCopy;
  }

  public function append($value) {
    if (is_integer($value)) {
      $value = chr($value&0xff);
    } elseif (!is_string($value)) {
      throw new TypeError(
        sprintf('value must be an integer or a string, %s given', gettype($value)),
      );
    } else {
      if (empty($value)) {
        return strlen($this->_data);
      }
    }

    $this->_data .= $value;
    return strlen($this->_data);
  }

  public function get($n = -1, $index = 0, $pad = false) {
    if (!is_integer($n)) {
      throw new TypeError(
        sprintf('n must be an integer, %s given', gettype($n)),
      );
    }
    if ($n < -1 || $n >= PHP_INT_MAX) {
      throw new InvalidArgumentException('n must be an integer in the range [-1, ' . PHP_INT_MAX . ']');
    }

    if (!is_integer($index)) {
      throw new TypeError(
        sprintf('index must be an integer, %s given', gettype($index)),
      );
    }
    if ($index < 0) {
      throw new InvalidArgumentException('index must be a non-negative integer');
    }

    if ($n === 0) {
      return '';
    }

    $s = '';
    if ($n < 0) {
      $s = substr($this->_data, $index);
    } else {
      $s = substr($this->_data, $index, $n);

      if ($pad && (strlen($s) < $n)) {
        $s = str_pad($s, $n, "\x00", STR_PAD_RIGHT);
      }
    }

    return $s;
  }

  // --------------------------------------------------

  #[\ReturnTypeWillChange]
  public function offsetExists($offset) {
    if (!is_integer($offset)) {
      throw new TypeError(
        sprintf('offset must be an integer, %s given', gettype($offset)),
      );
    }
    if ($offset < 0 || $offset > PHP_INT_MAX) {
      throw new InvalidArgumentException('offset must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $size = strlen($this->_data);
    if ($offset >= $size) {
      return false;
    }

    return true;
  }

  #[\ReturnTypeWillChange]
  public function offsetGet($offset) {
    if (!is_integer($offset)) {
      throw new TypeError(
        sprintf('offset must be an integer, %s given', gettype($offset)),
      );
    }
    if ($offset < 0 || $offset > PHP_INT_MAX) {
      throw new InvalidArgumentException('offset must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $size = strlen($this->_data);
    if ($offset >= $size) {
      return (int) 0;
    }

    return ord($this->_data[$offset]);
  }

  #[\ReturnTypeWillChange]
  public function offsetSet($offset, $value) {
    if (!is_integer($offset)) {
      throw new TypeError(
        sprintf('offset must be an integer, %s given', gettype($offset)),
      );
    }
    if ($offset < 0 || $offset > PHP_INT_MAX) {
      throw new InvalidArgumentException('offset must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $size = strlen($this->_data);
    if ($offset >= $size) {
      $this->adjust($offset);
    }

    if (is_string($value)) {
      $value = (!empty($value) ? (int) ord($value[0]) : (int) 0);
    } elseif (!is_integer($value)) {
      $value = (int) 0;
    }

    $this->_data[$offset] = chr(((int) $value)&0xff);
  }

  #[\ReturnTypeWillChange]
  public function offsetUnset($offset) {
    if (!is_integer($offset)) {
      throw new TypeError(
        sprintf('offset must be an integer, %s given', gettype($offset)),
      );
    }
    if ($offset < 0 || $offset > PHP_INT_MAX) {
      throw new InvalidArgumentException('offset must be an integer in the range [0, ' . PHP_INT_MAX . ']');
    }

    $size = strlen($this->_data);
    if ($offset >= $size) {
      return;
    }

    $this->_data[$offset] = "\x00";
  }
}
