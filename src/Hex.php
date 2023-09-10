<?php

namespace CrudeCrypto;

use CrudeCrypto\Bufferable;
use CrudeCrypto\HexException;
use TypeError;

class Hex {
  const NON_STRICT = 0;
  const DISALLOW_SPACE = (1 << 1);
  const DISALLOW_NEWLINE = (1 << 2);
  const ONLY_LOWERCASE = (1 << 3);
  const ONLY_UPPERCASE = (1 << 4);
  const ONLY_VALID_CHARSET = (1 << 5);
  const ALLOW_REMAINING_NIBBLE = (1 << 6);

  const ENCODE_DEFAULT = (0 << 0);
  const ENCODE_SPACES = (1 << 1);
  const ENCODE_HEADERS = (1 << 2);
  const ENCODE_HEADERS_LONG = (1 << 3);
  const ENCODE_PRINTABLE = (1 << 4);
  const ENCODE_UPPERCASE = (1 << 5);
  const ENCODE_SKIP_CR = (1 << 6);
  const ENCODE_ROW_MASK_SHIFT = (16);
  const ENCODE_ROW_MASK = (255 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_SINGLE = (0 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_4 = (4 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_8 = (8 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_16 = (16 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_32 = (32 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_64 = (64 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_ROW_128 = (128 << self::ENCODE_ROW_MASK_SHIFT);
  const ENCODE_PRETTY = (self::ENCODE_SPACES);
  const ENCODE_PRETTIER = (self::ENCODE_SPACES | self::ENCODE_HEADERS | self::ENCODE_ROW_8);
  const ENCODE_PRETTIEST = (self::ENCODE_SPACES | self::ENCODE_HEADERS | self::ENCODE_ROW_8 | self::ENCODE_PRINTABLE);

  public static function encode($data, $opts = 0) {
    $len = 0;
    if (is_string($data)) {
      $len = strlen($data);
    } elseif ($data instanceof Bufferable) {
      $len = $data->length();
    } else {
      throw new TypeError(
        sprintf('data must be a string or a ' . Bufferable::class . ', %s given', gettype($data)),
      );
    }

    if (!is_integer($opts)) {
      $opts = 0;
    }

    $optSpaces = (($opts&self::ENCODE_SPACES) !== 0);
    $optUC = (($opts&self::ENCODE_UPPERCASE) !== 0);
    $optHeaders = (($opts&self::ENCODE_HEADERS) !== 0);
    $optHeadersLong = (($opts&self::ENCODE_HEADERS_LONG) !== 0);
    $optPrintable = (($opts&self::ENCODE_PRINTABLE) !== 0);
    $optRowSize = (($opts&self::ENCODE_ROW_MASK) >> self::ENCODE_ROW_MASK_SHIFT);
    $optSkipCR = (($opts&self::ENCODE_SKIP_CR) !== 0);
    $optAnyPretty = ($optSpaces || $optHeaders || ($optRowSize > 0));

    $eol = ($optSkipCR ? "\n" : "\r\n");
    $headerFormat = ('%0' . ($optHeadersLong ? '16' : '8') . ($optUC ? 'X' : 'x') . "\t");
    $byteFormat = ('%02' . ($optUC ? 'X' : 'x'));

    $s = '';
    for ($i = 0; $i < $len; ++$i) {
      if ($optAnyPretty) {
        if ($optRowSize > 0 && ($i % $optRowSize) === 0) {
          if ($i !== 0) {
            $s .= $eol;
          }

          if ($optHeaders) {
            $s .= sprintf($headerFormat, $i);
          }
        } elseif ($optSpaces) {
          if ($i !== 0) {
            $s .= ' ';
          }
        }
      }

      $b = (($data instanceof Bufferable) ? $data[$i] : ord($data[$i]));
      if ($optPrintable && ($b >= 0x21 && $b <= 0x7e)) {
        $s .= '.';
        $s .= chr($b);
      } else {
        $s .= sprintf($byteFormat, $b);
      }
    }

    return $s;
  }

  public static function decode($hex, $strictness = 0) {
    if (!is_string($hex)) {
      throw new TypeError(
        sprintf('hex must be a string, %s given', gettype($hex)),
      );
    }

    if (!is_integer($strictness)) {
      $strictness = 0;
    }

    $len = strlen($hex);
    if ($len === 0) {
      return '';
    }

    $optDisallowSpace = (($strictness&self::DISALLOW_SPACE) !== 0);
    $optDisallowNewline = (($strictness&self::DISALLOW_NEWLINE) !== 0);
    $optOnlyValidCharset = (($strictness&self::ONLY_VALID_CHARSET) !== 0);
    $optOnlyUC = (($strictness&self::ONLY_UPPERCASE) !== 0);
    $optOnlyLC = (($strictness&self::ONLY_LOWERCASE) !== 0 && !$optOnlyUC);
    $optAllowRemNib = (($strictness&self::ALLOW_REMAINING_NIBBLE) !== 0);

    $s = '';
    $b = -1;
    $c = 0;
    for ($i = 0; $i < $len; ++$i) {
      $c = ord($hex[$i]);

      if ($c >= 97 && $c <= 102) {
        if ($optOnlyUC) {
          throw new HexException(HexException::ONLY_UPPERCASE);
        }

        // 'a'-'f'
        $c -= 87;
      } else if ($c >= 65 && $c <= 70) {
        if ($optOnlyLC) {
          throw new HexException(HexException::ONLY_LOWERCASE);
        }

        // 'A'-'F'
        $c -= 55;
      } else if ($c >= 48 && $c <= 57) {
        // '0'-'9'
        $c -= 48;
      } else {
        if ($optOnlyValidCharset) {
          throw new HexException(HexException::ONLY_VALID_CHARSET);
        }

        if ($c === 32) {
          // ' '
          if ($optDisallowSpace) {
            throw new HexException(HexException::DISALLOWED_SPACE);
          }
        } elseif ($c === 10) {
          // '\n'
          if ($optDisallowNewline) {
            throw new HexException(HexException::DISALLOWED_NEWLINE);
          }
        }

        continue;
      }

      if ($b < 0) {
        $b = $c;
      } else {
        $b <<= 4;
        $b |= $c;

        $s .= chr($b);
        $b = -1;
      }
    }

    if (!$optAllowRemNib && $b >= 0) {
      throw new HexException(HexException::ODD_NIBBLE);
    }

    return $s;
  }
}
