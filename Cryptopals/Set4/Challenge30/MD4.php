<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge30;

class MD4
{
    private function rol(int $x, int $n): int
    {
        return ($x << $n) | ($x >> (32 - $n));
    }

    private function body(MD4Context $context)
    {
        $words = array_values(unpack('V16', call_user_func_array('pack', array_merge(['C64'], $context->buffer))));

        $A = $a = $context->a;
        $B = $b = $context->b;
        $C = $c = $context->c;
        $D = $d = $context->d;

        $a = $this->rol($a + (($b & $c) | (~$b & $d)) + $words[0] & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | (~$a & $c)) + $words[1] & 0xffffffff, 7);
        $c = $this->rol($c + (($d & $a) | (~$d & $b)) + $words[2] & 0xffffffff, 11);
        $b = $this->rol($b + (($c & $d) | (~$c & $a)) + $words[3] & 0xffffffff, 19);
        $a = $this->rol($a + (($b & $c) | (~$b & $d)) + $words[4] & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | (~$a & $c)) + $words[5] & 0xffffffff, 7);
        $c = $this->rol($c + (($d & $a) | (~$d & $b)) + $words[6] & 0xffffffff, 11);
        $b = $this->rol($b + (($c & $d) | (~$c & $a)) + $words[7] & 0xffffffff, 19);
        $a = $this->rol($a + (($b & $c) | (~$b & $d)) + $words[8] & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | (~$a & $c)) + $words[9] & 0xffffffff, 7);
        $c = $this->rol($c + (($d & $a) | (~$d & $b)) + $words[10] & 0xffffffff, 11);
        $b = $this->rol($b + (($c & $d) | (~$c & $a)) + $words[11] & 0xffffffff, 19);
        $a = $this->rol($a + (($b & $c) | (~$b & $d)) + $words[12] & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | (~$a & $c)) + $words[13] & 0xffffffff, 7);
        $c = $this->rol($c + (($d & $a) | (~$d & $b)) + $words[14] & 0xffffffff, 11);
        $b = $this->rol($b + (($c & $d) | (~$c & $a)) + $words[15] & 0xffffffff, 19);

        $a = $this->rol($a + (($b & $c) | ($b & $d) | ($c & $d)) + $words[0] + 0x5a827999 & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | ($a & $c) | ($b & $c)) + $words[4] + 0x5a827999 & 0xffffffff, 5);
        $c = $this->rol($c + (($d & $a) | ($d & $b) | ($a & $b)) + $words[8] + 0x5a827999 & 0xffffffff, 9);
        $b = $this->rol($b + (($c & $d) | ($c & $a) | ($d & $a)) + $words[12] + 0x5a827999 & 0xffffffff, 13);
        $a = $this->rol($a + (($b & $c) | ($b & $d) | ($c & $d)) + $words[1] + 0x5a827999 & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | ($a & $c) | ($b & $c)) + $words[5] + 0x5a827999 & 0xffffffff, 5);
        $c = $this->rol($c + (($d & $a) | ($d & $b) | ($a & $b)) + $words[9] + 0x5a827999 & 0xffffffff, 9);
        $b = $this->rol($b + (($c & $d) | ($c & $a) | ($d & $a)) + $words[13] + 0x5a827999 & 0xffffffff, 13);
        $a = $this->rol($a + (($b & $c) | ($b & $d) | ($c & $d)) + $words[2] + 0x5a827999 & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | ($a & $c) | ($b & $c)) + $words[6] + 0x5a827999 & 0xffffffff, 5);
        $c = $this->rol($c + (($d & $a) | ($d & $b) | ($a & $b)) + $words[10] + 0x5a827999 & 0xffffffff, 9);
        $b = $this->rol($b + (($c & $d) | ($c & $a) | ($d & $a)) + $words[14] + 0x5a827999 & 0xffffffff, 13);
        $a = $this->rol($a + (($b & $c) | ($b & $d) | ($c & $d)) + $words[3] + 0x5a827999 & 0xffffffff, 3);
        $d = $this->rol($d + (($a & $b) | ($a & $c) | ($b & $c)) + $words[7] + 0x5a827999 & 0xffffffff, 5);
        $c = $this->rol($c + (($d & $a) | ($d & $b) | ($a & $b)) + $words[11] + 0x5a827999 & 0xffffffff, 9);
        $b = $this->rol($b + (($c & $d) | ($c & $a) | ($d & $a)) + $words[15] + 0x5a827999 & 0xffffffff, 13);

        $a = $this->rol($a + ($b ^ $c ^ $d) + $words[0] + 0x6ed9eba1 & 0xffffffff, 3);
        $d = $this->rol($d + ($a ^ $b ^ $c) + $words[8] + 0x6ed9eba1 & 0xffffffff, 9);
        $c = $this->rol($c + ($d ^ $a ^ $b) + $words[4] + 0x6ed9eba1 & 0xffffffff, 11);
        $b = $this->rol($b + ($c ^ $d ^ $a) + $words[12] + 0x6ed9eba1 & 0xffffffff, 15);
        $a = $this->rol($a + ($b ^ $c ^ $d) + $words[2] + 0x6ed9eba1 & 0xffffffff, 3);
        $d = $this->rol($d + ($a ^ $b ^ $c) + $words[10] + 0x6ed9eba1 & 0xffffffff, 9);
        $c = $this->rol($c + ($d ^ $a ^ $b) + $words[6] + 0x6ed9eba1 & 0xffffffff, 11);
        $b = $this->rol($b + ($c ^ $d ^ $a) + $words[14] + 0x6ed9eba1 & 0xffffffff, 15);
        $a = $this->rol($a + ($b ^ $c ^ $d) + $words[1] + 0x6ed9eba1 & 0xffffffff, 3);
        $d = $this->rol($d + ($a ^ $b ^ $c) + $words[9] + 0x6ed9eba1 & 0xffffffff, 9);
        $c = $this->rol($c + ($d ^ $a ^ $b) + $words[5] + 0x6ed9eba1 & 0xffffffff, 11);
        $b = $this->rol($b + ($c ^ $d ^ $a) + $words[13] + 0x6ed9eba1 & 0xffffffff, 15);
        $a = $this->rol($a + ($b ^ $c ^ $d) + $words[3] + 0x6ed9eba1 & 0xffffffff, 3);
        $d = $this->rol($d + ($a ^ $b ^ $c) + $words[11] + 0x6ed9eba1 & 0xffffffff, 9);
        $c = $this->rol($c + ($d ^ $a ^ $b) + $words[7] + 0x6ed9eba1 & 0xffffffff, 11);
        $b = $this->rol($b + ($c ^ $d ^ $a) + $words[15] + 0x6ed9eba1 & 0xffffffff, 15);

        $context->a = $a + $A & 0xffffffff;
        $context->b = $b + $B & 0xffffffff;
        $context->c = $c + $C & 0xffffffff;
        $context->d = $d + $D & 0xffffffff;
    }

    function init(MD4Context $context)
    {
        $context->a = 0x67452301;
        $context->b = 0xefcdab89;
        $context->c = 0x98badcfe;
        $context->d = 0x10325476;

        $context->lo = 0;
        $context->hi = 0;

        $context->buffer = array_fill(0, 64, 0);
    }

    function update(MD4Context $context, string $data)
    {
        $dataLen = strlen($data);
        $offset = 0;

        while ($offset < $dataLen) {
            $lo = $context->lo;

            $used = $lo & 0x3f;
            $available = 64 - $used;

            $size = min($available, $dataLen - $offset);

            if (($context->lo = ($lo + $size) & 0x1fffffff) < $lo) {
                $context->hi++;
            }

            array_splice($context->buffer, $used, $size, unpack("@$offset/C$size", $data));

            if ($size < $available) {
                return;
            }

            $this->body($context);

            $offset += $size;
        }
    }

    function result(MD4Context $context): string
    {
        $used = $context->lo & 0x3f;
        $context->buffer[$used++] = 0x80;
        $available = 64 - $used;

        if ($available < 8) {
            array_splice($context->buffer, $used, $available, array_fill(0, $available, 0));
            $this->body($context);
            $used = 0;
            $available = 64;
        }

        $available -= 8;

        if ($available) {
            array_splice($context->buffer, $used, $available, array_fill(0, $available, 0));
        }

        $context->lo <<= 3;

        array_splice($context->buffer, 56, 8, [
            $context->lo, $context->lo >> 8, $context->lo >> 16, $context->lo >> 24,
            $context->hi, $context->hi >> 8, $context->hi >> 16, $context->hi >> 24
        ]);

        $this->body($context);

        return pack('C16',
            $context->a, $context->a >> 8, $context->a >> 16, $context->a >> 24,
            $context->b, $context->b >> 8, $context->b >> 16, $context->b >> 24,
            $context->c, $context->c >> 8, $context->c >> 16, $context->c >> 24,
            $context->d, $context->d >> 8, $context->d >> 16, $context->d >> 24
        );
    }
}
