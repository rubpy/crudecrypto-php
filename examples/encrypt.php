<?php

require_once dirname(__FILE__) . '/common.php';

use CrudeCrypto\AES\AES128;
use CrudeCrypto\AES\AES192;
use CrudeCrypto\AES\AES256;
use CrudeCrypto\Bufferable;
use CrudeCrypto\Console;
use CrudeCrypto\Hex;
use CrudeCrypto\PKCS7;

// --------------------------------------------------

$example = [
  'cipher_size' => 256,
  'key' => 'Ub8Je@x_Z6$&6A3RfLE8gm-#AE8DdZh3',
  'input' => 'Lorem ipsum dolor sit amet',
  // 'iv' => Hex::decode('92 28 26 99 73 6e a5 0a c2 13 81 c9 bf c1 cd fe'),
  'pad' => true,
];

// --------------------------------------------------

$doEncrypt = function ($debugMode, &$data, $key, $iv, $pad, $cipherSize = 0) {
  if (!is_string($data) && !($data instanceof Bufferable)) {
    throw new TypeError(
      sprintf('data must be a string or a ' . Bufferable::class . ', %s given', gettype($data)),
    );
  }

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

  if (!is_integer($cipherSize) || $cipherSize <= 0) {
    $cipherSize = (strlen($key) * 8);
  }

  if ($debugMode) {
    Console::println('== MODE ======================', 34);
    Console::println('aes-' . $cipherSize . '-cbc' . ($pad ? '-pkcs7' : '') . (!empty($iv) ? ' (with custom IV)' : ''));
    Console::println();

    Console::println('== KEY =======================', 90);
    Console::println(Hex::encode($key, Hex::ENCODE_PRETTIEST));
    Console::println('(' . Hex::encode($key, Hex::ENCODE_SPACES) . ')');
    Console::println();

    if (!empty($iv)) {
      Console::println('== IV =======================', 96);
      Console::println(Hex::encode($iv, Hex::ENCODE_PRETTIEST));
      Console::println('(' . Hex::encode($iv, Hex::ENCODE_SPACES) . ')');
      Console::println();
    }

    Console::println('== INPUT =======================', 92);
    Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
    Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
    Console::println();
  }

  $enc = null;
  switch ($cipherSize) {
  case 128:
    $enc = new AES128($key, $iv);
    break;
  case 192:
    $enc = new AES192($key, $iv);
    break;
  case 256:
    $enc = new AES256($key, $iv);
    break;

  default:
    throw new InvalidArgumentException('unsupported encryption key size');
  }

  if ($pad) {
    PKCS7::pad($data, $enc::getBlockLength());

    if ($debugMode) {
      Console::println('== INPUT (PKCS7-padded) ========', 93);
      Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
      Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
      Console::println();
    }
  }

  $enc->encrypt($data, 'cbc');

  if ($debugMode) {
    Console::println('== ENCRYPTED ===================', 91);
    Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
    Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
    Console::println();
  }
};

$doEncrypt(
  true,
  $example['input'],
  $example['key'],
  (isset($example['iv']) ? $example['iv'] : ''),
  (isset($example['pad']) ? $example['pad'] : false),
  (isset($example['cipher_size']) ? $example['cipher_size'] : 0),
);
