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
  'encrypted' => Hex::decode('76 07 fa 40 84 94 ba d2 32 5f 9a 49 e3 8e 96 43 78 73 f2 b9 4a f9 d3 f2 43 d5 4d 05 81 eb 97 d5'),
  // 'iv' => Hex::decode('92 28 26 99 73 6e a5 0a c2 13 81 c9 bf c1 cd fe'),
  'unpad' => true,
];

// --------------------------------------------------

$doDecrypt = function ($debugMode, &$data, $key, $iv, $unpad, $cipherSize = 0) {
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
    Console::println('aes-' . $cipherSize . '-cbc' . ($unpad ? '-pkcs7' : '') . (!empty($iv) ? ' (with custom IV)' : ''));
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

    Console::println('== ENCRYPTED =======================', 92);
    Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
    Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
    Console::println();
  }

  $dec = null;
  switch ($cipherSize) {
  case 128:
    $dec = new AES128($key, $iv);
    break;
  case 192:
    $dec = new AES192($key, $iv);
    break;
  case 256:
    $dec = new AES256($key, $iv);
    break;

  default:
    throw new InvalidArgumentException('unsupported decryption key size');
  }

  $dec->decrypt($data, 'cbc');

  if ($unpad) {
    if ($debugMode) {
      Console::println('== DECRYPTED (PKCS7-padded) ========', 93);
      Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
      Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
      Console::println();
    }

    PKCS7::unpad($data, $dec::getBlockLength());
  }

  if ($debugMode) {
    Console::println('== DECRYPTED ===================', 91);
    Console::println(Hex::encode($data, Hex::ENCODE_PRETTIEST));
    Console::println('(' . Hex::encode($data, Hex::ENCODE_SPACES) . ')');
    Console::println();
  }
};

$doDecrypt(
  true,
  $example['encrypted'],
  $example['key'],
  (isset($example['iv']) ? $example['iv'] : ''),
  (isset($example['unpad']) ? $example['unpad'] : false),
  (isset($example['cipher_size']) ? $example['cipher_size'] : 0),
);
