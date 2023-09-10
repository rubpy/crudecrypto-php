<?php

namespace CrudeCrypto\AES;

use CrudeCrypto\AES\Exceptions\InvalidInputSizeException;
use CrudeCrypto\AES\Exceptions\InvalidIVSizeException;
use CrudeCrypto\AES\Exceptions\InvalidKeySizeException;
use CrudeCrypto\AES\Exceptions\TypeError;
use CrudeCrypto\AES\Exceptions\UnsupportedModeException;
use CrudeCrypto\Buffer;
use CrudeCrypto\Bufferable;
use CrudeCrypto\BufferCursor;
use CrudeCrypto\Cipher;

abstract class AES implements Cipher {
  const MODE_CBC = 'cbc';

  const BLOCK_LENGTH = 16;
  const DEFAULT_IV =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
  const SBOX =
    "\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76" .
    "\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0" .
    "\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15" .
    "\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75" .
    "\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84" .
    "\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf" .
    "\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8" .
    "\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2" .
    "\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73" .
    "\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb" .
    "\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79" .
    "\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08" .
    "\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a" .
    "\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e" .
    "\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf" .
    "\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16";

  const RSBOX =
    "\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb" .
    "\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb" .
    "\x54\x7b\x94\x32\xa6\xc2\x23\x3d\xee\x4c\x95\x0b\x42\xfa\xc3\x4e" .
    "\x08\x2e\xa1\x66\x28\xd9\x24\xb2\x76\x5b\xa2\x49\x6d\x8b\xd1\x25" .
    "\x72\xf8\xf6\x64\x86\x68\x98\x16\xd4\xa4\x5c\xcc\x5d\x65\xb6\x92" .
    "\x6c\x70\x48\x50\xfd\xed\xb9\xda\x5e\x15\x46\x57\xa7\x8d\x9d\x84" .
    "\x90\xd8\xab\x00\x8c\xbc\xd3\x0a\xf7\xe4\x58\x05\xb8\xb3\x45\x06" .
    "\xd0\x2c\x1e\x8f\xca\x3f\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8a\x6b" .
    "\x3a\x91\x11\x41\x4f\x67\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6\x73" .
    "\x96\xac\x74\x22\xe7\xad\x35\x85\xe2\xf9\x37\xe8\x1c\x75\xdf\x6e" .
    "\x47\xf1\x1a\x71\x1d\x29\xc5\x89\x6f\xb7\x62\x0e\xaa\x18\xbe\x1b" .
    "\xfc\x56\x3e\x4b\xc6\xd2\x79\x20\x9a\xdb\xc0\xfe\x78\xcd\x5a\xf4" .
    "\x1f\xdd\xa8\x33\x88\x07\xc7\x31\xb1\x12\x10\x59\x27\x80\xec\x5f" .
    "\x60\x51\x7f\xa9\x19\xb5\x4a\x0d\x2d\xe5\x7a\x9f\x93\xc9\x9c\xef" .
    "\xa0\xe0\x3b\x4d\xae\x2a\xf5\xb0\xc8\xeb\xbb\x3c\x83\x53\x99\x61" .
    "\x17\x2b\x04\x7e\xba\x77\xd6\x26\xe1\x69\x14\x63\x55\x21\x0c\x7d";

  const RCON =
    "\x8d\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" .
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

  protected Bufferable $roundKey; // uint8_t[static::getRoundKeySize()]
  protected Bufferable $iv; // uint8_t[static::getBlockLength()]

  public function __construct(
    #[\SensitiveParameter]
    $key,
    #[\SensitiveParameter]
    $iv = '') {
    if (!is_string($key)) {
      throw new TypeError(
        sprintf('key must be a string, %s given', gettype($key)),
      );
    }
    if (!is_string($iv)) {
      throw new TypeError(
        sprintf('iv must be a string, %s given', gettype($iv)),
      );
    }

    $keyLength = strlen($key);
    if ($keyLength !== static::getKeySize()) {
      throw new InvalidKeySizeException('key must be ' . static::getKeySize() . ' bytes long');
    }

    $ivLength = strlen($iv);
    if ($ivLength === 0) {
      $iv = static::DEFAULT_IV;
    } elseif ($ivLength !== static::getBlockLength()) {
      throw new InvalidIVSizeException('iv must be ' . static::getBlockLength() . ' bytes long');
    }

    $this->iv = new Buffer();
    $this->iv->insert($iv);

    $roundKey = self::expandKey($key);
    $this->roundKey = new Buffer();
    $this->roundKey->insert($roundKey);
  }

  public static function getBlockLength() {
    return self::BLOCK_LENGTH;
  }

  abstract protected static function getRoundNum();
  abstract protected static function getKeyWordSize();
  protected static function getKeySize() {return static::getKeyWordSize() * 4;}
  abstract protected static function getRoundKeySize();

  protected static function expandKey(
    #[\SensitiveParameter]
    $key) {
    if (!is_string($key)) {
      throw new TypeError(
        sprintf('key must be a string, %s given', gettype($key)),
      );
    }

    $roundKeySize = static::getRoundKeySize();
    $roundKey = str_repeat("\x00", $roundKeySize);
    $n = min(strlen($key), $roundKeySize);
    for ($i = 0; $i < $n; ++$i) {
      $roundKey[$i] = $key[$i];
    }

    $keyWordSize = static::getKeyWordSize();
    $tt = [0, 0, 0, 0];
    $m = ($keyWordSize * (static::getRoundNum() + 1));

    for ($i = $keyWordSize; $i < $m; ++$i) {
      $t = (($i - 1) * 4);

      $tt[0] = ord($roundKey[$t + 0]);
      $tt[1] = ord($roundKey[$t + 1]);
      $tt[2] = ord($roundKey[$t + 2]);
      $tt[3] = ord($roundKey[$t + 3]);

      if ($i % $keyWordSize === 0) {
        $t = $tt[0];
        $tt[0] = $tt[1];
        $tt[1] = $tt[2];
        $tt[2] = $tt[3];
        $tt[3] = $t;

        $tt[0] = ord(self::SBOX[$tt[0]]);
        $tt[1] = ord(self::SBOX[$tt[1]]);
        $tt[2] = ord(self::SBOX[$tt[2]]);
        $tt[3] = ord(self::SBOX[$tt[3]]);

        $tt[0] ^= ord(self::RCON[($i / $keyWordSize)]);
      }

      if ($keyWordSize >= 8) {
        if ($i % $keyWordSize === 4) {
          $tt[0] = ord(self::SBOX[$tt[0]]);
          $tt[1] = ord(self::SBOX[$tt[1]]);
          $tt[2] = ord(self::SBOX[$tt[2]]);
          $tt[3] = ord(self::SBOX[$tt[3]]);
        }
      }

      $t = (($i - $keyWordSize) * 4);
      $j = ($i * 4);

      $roundKey[$j + 0] = chr(ord($roundKey[$t + 0]) ^ $tt[0]);
      $roundKey[$j + 1] = chr(ord($roundKey[$t + 1]) ^ $tt[1]);
      $roundKey[$j + 2] = chr(ord($roundKey[$t + 2]) ^ $tt[2]);
      $roundKey[$j + 3] = chr(ord($roundKey[$t + 3]) ^ $tt[3]);
    }

    return $roundKey;
  }

  protected static function xorWithIV(Bufferable $buf, Bufferable $iv) {
    $blockLen = static::getBlockLength();

    for ($i = 0; $i < $blockLen; ++$i) {
      $buf[$i] = ($buf[$i] ^ $iv[$i]);
    }
  }

  protected static function addRoundKey(Bufferable $state, Bufferable $roundKey, $round) {
    for ($i = 0; $i < 4; ++$i) {
      for ($j = 0; $j < 4; ++$j) {
        $x = ($i * 4 + $j);
        $y = (($round * 4 * 4) + ($i * 4) + $j);

        $state[$x] = ($state[$x] ^ $roundKey[$y]);
      }
    }
  }

  protected static function subBytes(Bufferable $state) {
    for ($i = 0; $i < 4; ++$i) {
      for ($j = 0; $j < 4; ++$j) {
        $x = ($j * 4 + $i);

        $state[$x] = ord(self::SBOX[$state[$x]]);
      }
    }
  }

  protected static function invSubBytes(Bufferable $state) {
    for ($i = 0; $i < 4; ++$i) {
      for ($j = 0; $j < 4; ++$j) {
        $x = ($j * 4 + $i);

        $state[$x] = ord(self::RSBOX[$state[$x]]);
      }
    }
  }

  protected static function shiftRows(Bufferable $state) {
    $t = $state[0 * 4 + 1];
    $state[0 * 4 + 1] = $state[1 * 4 + 1];
    $state[1 * 4 + 1] = $state[2 * 4 + 1];
    $state[2 * 4 + 1] = $state[3 * 4 + 1];
    $state[3 * 4 + 1] = $t;

    $t = $state[0 * 4 + 2];
    $state[0 * 4 + 2] = $state[2 * 4 + 2];
    $state[2 * 4 + 2] = $t;

    $t = $state[1 * 4 + 2];
    $state[1 * 4 + 2] = $state[3 * 4 + 2];
    $state[3 * 4 + 2] = $t;

    $t = $state[0 * 4 + 3];
    $state[0 * 4 + 3] = $state[3 * 4 + 3];
    $state[3 * 4 + 3] = $state[2 * 4 + 3];
    $state[2 * 4 + 3] = $state[1 * 4 + 3];
    $state[1 * 4 + 3] = $t;
  }

  protected static function invShiftRows(Bufferable $state) {
    $t = $state[3 * 4 + 1];
    $state[3 * 4 + 1] = $state[2 * 4 + 1];
    $state[2 * 4 + 1] = $state[1 * 4 + 1];
    $state[1 * 4 + 1] = $state[0 * 4 + 1];
    $state[0 * 4 + 1] = $t;

    $t = $state[0 * 4 + 2];
    $state[0 * 4 + 2] = $state[2 * 4 + 2];
    $state[2 * 4 + 2] = $t;

    $t = $state[1 * 4 + 2];
    $state[1 * 4 + 2] = $state[3 * 4 + 2];
    $state[3 * 4 + 2] = $t;

    $t = $state[0 * 4 + 3];
    $state[0 * 4 + 3] = $state[1 * 4 + 3];
    $state[1 * 4 + 3] = $state[2 * 4 + 3];
    $state[2 * 4 + 3] = $state[3 * 4 + 3];
    $state[3 * 4 + 3] = $t;
  }

  protected static function xtime($x) {
    $a = ((int) $x << 1);
    $b = ((int) ((((int) $x >> 7)&1) * 0x1b));

    $x = (((int) ($a ^ $b)));
    return $x;
  }

  protected static function xtimeMultiply($x) {
    $xm = [$x, 0, 0, 0, 0];
    for ($i = 1; $i < 5; ++$i) {
      $xm[$i] = self::xtime($xm[$i - 1]);
    }

    return $xm;
  }

  protected static function mixColumns(Bufferable $state) {
    $a = 0;
    $b = 0;
    $c = 0;
    $d = 0;

    for ($i = 0; $i < 4; ++$i) {
      $p = ($i * 4);
      $a = $state[$p + 0];

      {
        $b = $state[$p + 0];
        $b = ($b ^ $state[$p + 1]);
        $b = ($b ^ $state[$p + 2]);
        $b = ($b ^ $state[$p + 3]);
      }

      {
        $c = ($state[$p + 0] ^ $state[$p + 1]);
        $c = self::xtime($c);
        $state[$p + 0] = (($state[$p + 0] ^ $c) ^ $b);

        $c = ($state[$p + 1] ^ $state[$p + 2]);
        $c = self::xtime($c);
        $state[$p + 1] = (($state[$p + 1] ^ $c) ^ $b);

        $c = ($state[$p + 2] ^ $state[$p + 3]);
        $c = self::xtime($c);
        $state[$p + 2] = (($state[$p + 2] ^ $c) ^ $b);

        $c = ($state[$p + 3] ^ $a);
        $c = self::xtime($c);
        $state[$p + 3] = (($state[$p + 3] ^ $c) ^ $b);
      }
    }
  }

  protected static function invMixColumns(Bufferable $state) {
    $a = 0;
    $b = 0;
    $c = 0;
    $d = 0;

    for ($i = 0; $i < 4; ++$i) {
      $p = ($i * 4);

      $a = $state[$p + 0];
      $b = $state[$p + 1];
      $c = $state[$p + 2];
      $d = $state[$p + 3];

      $ax = self::xtimeMultiply($a);
      $bx = self::xtimeMultiply($b);
      $cx = self::xtimeMultiply($c);
      $dx = self::xtimeMultiply($d);

      $t = 0;

      {
        $t = (((int) ($ax[1] ^ $ax[2] ^ $ax[3]))&0xff); // mul(a, 0x0e)
        $t ^= (((int) ($bx[0] ^ $bx[1] ^ $bx[3]))&0xff); // mul(b, 0x0b)
        $t ^= (((int) ($cx[0] ^ $cx[2] ^ $cx[3]))&0xff); // mul(c, 0x0d)
        $t ^= (((int) ($dx[0] ^ $dx[3]))&0xff); // mul(d, 0x09)
        $state[$p + 0] = $t;
      }
      {
        $t = (((int) ($ax[0] ^ $ax[3]))&0xff); // mul(a, 0x09)
        $t ^= (((int) ($bx[1] ^ $bx[2] ^ $bx[3]))&0xff); // mul(b, 0x0e)
        $t ^= (((int) ($cx[0] ^ $cx[1] ^ $cx[3]))&0xff); // mul(c, 0x0b)
        $t ^= (((int) ($dx[0] ^ $dx[2] ^ $dx[3]))&0xff); // mul(d, 0x0d)
        $state[$p + 1] = $t;
      }
      {
        $t = (((int) ($ax[0] ^ $ax[2] ^ $ax[3]))&0xff); // mul(a, 0x0d)
        $t ^= (((int) ($bx[0] ^ $bx[3]))&0xff); // mul(b, 0x09)
        $t ^= (((int) ($cx[1] ^ $cx[2] ^ $cx[3]))&0xff); // mul(c, 0x0e)
        $t ^= (((int) ($dx[0] ^ $dx[1] ^ $dx[3]))&0xff); // mul(d, 0x0b)
        $state[$p + 2] = $t;
      }
      {
        $t = (((int) ($ax[0] ^ $ax[1] ^ $ax[3]))&0xff); // mul(a, 0x0b)
        $t ^= (((int) ($bx[0] ^ $bx[2] ^ $bx[3]))&0xff); // mul(b, 0x0d)
        $t ^= (((int) ($cx[0] ^ $cx[3]))&0xff); // mul(c, 0x09)
        $t ^= (((int) ($dx[1] ^ $dx[2] ^ $dx[3]))&0xff); // mul(d, 0x0e)
        $state[$p + 3] = $t;
      }
    }
  }

  protected static function cipher(
    Bufferable $state,
    #[\SensitiveParameter]
    Bufferable $roundKey) {
    $round = 0;
    self::addRoundKey($state, $roundKey, $round++);

    $roundNum = static::getRoundNum();
    for (;; ++$round) {
      self::subBytes($state);
      self::shiftRows($state);

      if ($round === $roundNum) {
        break;
      }

      self::mixColumns($state);
      self::addRoundKey($state, $roundKey, $round);
    }

    self::addRoundKey($state, $roundKey, $round);
  }

  protected static function invCipher(
    Bufferable $state,
    #[\SensitiveParameter]
    Bufferable $roundKey) {
    $round = static::getRoundNum();
    self::addRoundKey($state, $roundKey, $round--);

    for (;; --$round) {
      self::invShiftRows($state);
      self::invSubBytes($state);

      self::addRoundKey($state, $roundKey, $round);
      if ($round === 0) {
        break;
      }

      self::invMixColumns($state);
    }
  }

  public function getSupportedModes() {
    return [
      static::MODE_CBC,
    ];
  }

  public function encrypt(
    #[\SensitiveParameter]
     &$input,
    $mode) {
    $supportedModes = $this->getSupportedModes();
    if (!is_string($mode)) {
      throw new TypeError(
        sprintf('mode must be a string, %s given', gettype($mode)),
      );
    }
    if (empty($mode) || !in_array($mode, $supportedModes)) {
      throw new UnsupportedModeException('mode must be one of the supported modes: [' . implode(', ', $supportedModes) . ']');
    }

    switch ($mode) {
    case static::MODE_CBC:
      return $this->encryptCBC($input);
      break;
    }

    throw new UnsupportedModeException('unsupported mode');
  }

  public function decrypt(
    #[\SensitiveParameter]
     &$input,
    $mode) {
    $supportedModes = $this->getSupportedModes();
    if (!is_string($mode)) {
      throw new TypeError(
        sprintf('mode must be a string, %s given', gettype($mode)),
      );
    }
    if (empty($mode) || !in_array($mode, $supportedModes)) {
      throw new UnsupportedModeException('mode must be one of the supported modes: [' . implode(', ', $supportedModes) . ']');
    }

    switch ($mode) {
    case static::MODE_CBC:
      return $this->decryptCBC($input);
      break;
    }

    throw new UnsupportedModeException('unsupported mode');
  }

  public function encryptCBC(
    #[\SensitiveParameter]
     &$input) {
    $buffer = $input;
    if (!($input instanceof Bufferable)) {
      if (!is_string($buffer)) {
        throw new TypeError(
          sprintf('input must be a string or a ' . Bufferable::class . ', %s given', gettype($buffer)),
        );
      }

      $buffer = new Buffer(-1, $input);
    }

    $cursor = new BufferCursor($buffer, 0);

    $blockLen = static::getBlockLength();
    $len = $cursor->length();
    if ($len % $blockLen !== 0) {
      throw new InvalidInputSizeException('input must be a multiple of ' . $blockLen . ' bytes');
    }

    $iv = $this->iv;
    for ($i = 0; $i < $len; $i += $blockLen) {
      self::xorWithIV($cursor, $iv);
      self::cipher($cursor, $this->roundKey);

      $cursor->copy($iv, $blockLen, 0, false, 0);
      $cursor->move($blockLen);
    }

    $this->iv = $iv;
  }

  public function decryptCBC(
    #[\SensitiveParameter]
     &$input) {
    $buffer = $input;
    if (!($input instanceof Bufferable)) {
      if (!is_string($buffer)) {
        throw new TypeError(
          sprintf('input must be a string or a ' . Bufferable::class . ', %s given', gettype($buffer)),
        );
      }

      $buffer = new Buffer(-1, $input);
    }

    $cursor = new BufferCursor($buffer, 0);

    $blockLen = static::getBlockLength();
    $len = $cursor->length();
    if ($len % $blockLen !== 0) {
      throw new InvalidInputSizeException('input must be a multiple of ' . $blockLen . ' bytes');
    }

    $iv = $this->iv;
    $niv = new Buffer($blockLen);
    for ($i = 0; $i < $len; $i += $blockLen) {
      $cursor->copy($niv, $blockLen, 0, false, 0);

      self::invCipher($cursor, $this->roundKey);
      self::xorWithIV($cursor, $iv);

      $niv->copy($iv, $blockLen, 0, false, 0);
      $cursor->move($blockLen);
    }

    $this->iv = $iv;
  }
}
