## 🗝 CrudeCrypto (PHP)
A native *PHP 7-8* **AES** (*Advanced Encryption Standard*) algorithm implementation.

Written mostly for fun, while reading up on block ciphers. 🤷‍♂️

------------------------------
This repository also features a bunch of utility classes, e.g.: `Buffer`, `BufferCursor`, `Hex`, `PKCS7`...

> ⚠️ Needless to say, __do not__ use this in production. This package is for
> educational (and entertainment, too) purposes only.

> NOTE: actual implementation of the *AES* algorithm is (more or less) based on
> **[kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c)**.

### Usage
#### Encryption
```php
<?php

$key = 'MK3BK6xCy#veUA!fvXfZ%vhExe9HVafq';
$data = 'Lorem ipsum dolor sit amet';
$iv = '';

// ------------------------------

$enc = new CrudeCrypto\AES\AES256($key, $iv);

CrudeCrypto\PKCS7::pad($data, $enc::getBlockLength());
$enc->encrypt($data, 'cbc');

// ------------------------------

/*
 Outputs:
   f0e9e0402615a32cd50dc9299977bc8ba186f35f424fecc9de10c8b7ae06f7a8
*/
echo CrudeCrypto\Hex::encode($data);
echo PHP_EOL;
```
#### Decryption
```php
<?php

$key = 'MK3BK6xCy#veUA!fvXfZ%vhExe9HVafq';
$data = CrudeCrypto\Hex::decode('f0e9e0402615a32cd50dc9299977bc8ba186f35f424fecc9de10c8b7ae06f7a8');
$iv = '';

// ------------------------------

$dec = new CrudeCrypto\AES\AES256($key, $iv);

$dec->decrypt($data, 'cbc');
CrudeCrypto\PKCS7::unpad($data, $dec::getBlockLength());

// ------------------------------

/*
 Outputs:
  4c6f72656d20697073756d20646f6c6f722073697420616d6574
*/
echo CrudeCrypto\Hex::encode($data);
echo PHP_EOL;
```

### Example
> 💡 NOTE: you can run these quick examples in an isolated Docker environment, like this:
```console
$ docker run -it --rm -v "$PWD":/usr/src/app:ro -w /usr/src/app php:8.2-cli php examples/encrypt.php
```

```console
$ php examples/encrypt.php
== MODE ======================
aes-256-cbc-pkcs7

== KEY =======================
00000000  .U .b .8 .J .e .@ .x ._
00000008  .Z .6 .$ .& .6 .A .3 .R
00000010  .f .L .E .8 .g .m .- .#
00000018  .A .E .8 .D .d .Z .h .3
(55 62 38 4a 65 40 78 5f 5a 36 24 26 36 41 33 52 66 4c 45 38 67 6d 2d 23 41 45 38 44 64 5a 68 33)

== INPUT =======================
00000000  .L .o .r .e .m 20 .i .p
00000008  .s .u .m 20 .d .o .l .o
00000010  .r 20 .s .i .t 20 .a .m
00000018  .e .t
(4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f 72 20 73 69 74 20 61 6d 65 74)

== INPUT (PKCS7-padded) ========
00000000  .L .o .r .e .m 20 .i .p
00000008  .s .u .m 20 .d .o .l .o
00000010  .r 20 .s .i .t 20 .a .m
00000018  .e .t 06 06 06 06 06 06
(4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f 72 20 73 69 74 20 61 6d 65 74 06 06 06 06 06 06)

== ENCRYPTED ===================
00000000  .v 07 fa .@ 84 94 ba d2
00000008  .2 ._ 9a .I e3 8e 96 .C
00000010  .x .s f2 b9 .J f9 d3 f2
00000018  .C d5 .M 05 81 eb 97 d5
(76 07 fa 40 84 94 ba d2 32 5f 9a 49 e3 8e 96 43 78 73 f2 b9 4a f9 d3 f2 43 d5 4d 05 81 eb 97 d5)
```
```console
$ php examples/decrypt.php
== MODE ======================
aes-256-cbc-pkcs7

== KEY =======================
00000000  .U .b .8 .J .e .@ .x ._
00000008  .Z .6 .$ .& .6 .A .3 .R
00000010  .f .L .E .8 .g .m .- .#
00000018  .A .E .8 .D .d .Z .h .3
(55 62 38 4a 65 40 78 5f 5a 36 24 26 36 41 33 52 66 4c 45 38 67 6d 2d 23 41 45 38 44 64 5a 68 33)

== ENCRYPTED =======================
00000000  .v 07 fa .@ 84 94 ba d2
00000008  .2 ._ 9a .I e3 8e 96 .C
00000010  .x .s f2 b9 .J f9 d3 f2
00000018  .C d5 .M 05 81 eb 97 d5
(76 07 fa 40 84 94 ba d2 32 5f 9a 49 e3 8e 96 43 78 73 f2 b9 4a f9 d3 f2 43 d5 4d 05 81 eb 97 d5)

== DECRYPTED (PKCS7-padded) ========
00000000  .L .o .r .e .m 20 .i .p
00000008  .s .u .m 20 .d .o .l .o
00000010  .r 20 .s .i .t 20 .a .m
00000018  .e .t 06 06 06 06 06 06
(4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f 72 20 73 69 74 20 61 6d 65 74 06 06 06 06 06 06)

== DECRYPTED ===================
00000000  .L .o .r .e .m 20 .i .p
00000008  .s .u .m 20 .d .o .l .o
00000010  .r 20 .s .i .t 20 .a .m
00000018  .e .t
(4c 6f 72 65 6d 20 69 70 73 75 6d 20 64 6f 6c 6f 72 20 73 69 74 20 61 6d 65 74)
```

### Testing
```console
$ ./vendor/bin/phpunit --colors=auto --testdox tests
PHPUnit 10.3.3 by Sebastian Bergmann and contributors.

Runtime:       PHP 8.2.9

.................................................                 49 / 49 (100%)

Time: 00:00.209, Memory: 8.00 MB

AES (CrudeCrypto\Tests\AES)
 ✔ Encryption with aes-128-cbc,····no·padding,·16-byte·key,···16-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-128-cbc,····no·padding,·16-byte·key,···15-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-128-cbc,····no·padding,·15-byte·key,···16-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,····4-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,···15-byte·input,···custom·IV·--->·success
 ✔ Encryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,···15-byte·input,···custom·IV·--->·exception
 ✔ Encryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,··255-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-128-cbc,····no·padding,·16-byte·key,··256-byte·input,···custom·IV·--->·success
 ✔ Encryption with aes-192-cbc,····no·padding,·24-byte·key,···16-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-192-cbc,····no·padding,·24-byte·key,···15-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-192-cbc,····no·padding,·23-byte·key,···16-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,····4-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,···15-byte·input,···custom·IV·--->·success
 ✔ Encryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,···15-byte·input,···custom·IV·--->·exception
 ✔ Encryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,··255-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-192-cbc,····no·padding,·24-byte·key,··256-byte·input,···custom·IV·--->·success
 ✔ Encryption with aes-256-cbc,····no·padding,·32-byte·key,···16-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-256-cbc,····no·padding,·32-byte·key,···15-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-256-cbc,····no·padding,·31-byte·key,···16-byte·input,··default·IV·--->·exception
 ✔ Encryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,····4-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,···15-byte·input,···custom·IV·--->·success
 ✔ Encryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,···15-byte·input,···custom·IV·--->·exception
 ✔ Encryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,··255-byte·input,··default·IV·--->·success
 ✔ Encryption with aes-256-cbc,····no·padding,·32-byte·key,··256-byte·input,···custom·IV·--->·success
 ✔ Decryption with aes-128-cbc,····no·padding,·16-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-128-cbc,····no·padding,·15-byte·key,···16-byte·ciphertext,··default·IV·--->·exception
 ✔ Decryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,···16-byte·ciphertext,···custom·IV·--->·success
 ✔ Decryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,···16-byte·ciphertext,···custom·IV·--->·exception
 ✔ Decryption with aes-128-cbc,·PKCS7·padding,·16-byte·key,··256-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-128-cbc,····no·padding,·16-byte·key,··256-byte·ciphertext,···custom·IV·--->·success
 ✔ Decryption with aes-192-cbc,····no·padding,·24-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-192-cbc,····no·padding,·23-byte·key,···16-byte·ciphertext,··default·IV·--->·exception
 ✔ Decryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,···16-byte·ciphertext,···custom·IV·--->·success
 ✔ Decryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,···16-byte·ciphertext,···custom·IV·--->·exception
 ✔ Decryption with aes-192-cbc,·PKCS7·padding,·24-byte·key,··256-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-192-cbc,····no·padding,·24-byte·key,··256-byte·ciphertext,···custom·IV·--->·success
 ✔ Decryption with aes-256-cbc,····no·padding,·32-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-256-cbc,····no·padding,·31-byte·key,···16-byte·ciphertext,··default·IV·--->·exception
 ✔ Decryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,···16-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,···16-byte·ciphertext,···custom·IV·--->·success
 ✔ Decryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,···16-byte·ciphertext,···custom·IV·--->·exception
 ✔ Decryption with aes-256-cbc,·PKCS7·padding,·32-byte·key,··256-byte·ciphertext,··default·IV·--->·success
 ✔ Decryption with aes-256-cbc,····no·padding,·32-byte·key,··256-byte·ciphertext,···custom·IV·--->·success

PKCS7 (CrudeCrypto\Tests\PKCS7)
 ✔ Pad with 1·byte(s)·of·padding
 ✔ Pad with 15·byte(s)·of·padding
 ✔ Unpad with 1·byte(s)·of·padding
 ✔ Unpad with 15·byte(s)·of·padding

OK (49 tests, 94 assertions)
```

### TODO
+ more unit tests (and better organized, too)
+ documentation (i.e., add PHPDoc comments)
