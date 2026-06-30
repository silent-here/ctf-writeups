<?php
$sock = '/run/keeper/keeper.sock';
$out = '/var/www/html/wp-content/uploads/kf_result.txt';
$last_keeper_error = '';

function keeper_talk($line) {
    global $sock, $last_keeper_error;
    $fp = @stream_socket_client('unix://' . $sock, $errno, $errstr, 2);
    if (!$fp) {
        $last_keeper_error = "errno=$errno errstr=$errstr";
        return 'ERR connect';
    }
    fwrite($fp, $line);
    $reply = trim((string) fgets($fp, 65536));
    fclose($fp);
    return $reply;
}

function u32($x) {
    return $x & 0xffffffff;
}

function rotr($x, $n) {
    return u32(($x >> $n) | (($x << (32 - $n)) & 0xffffffff));
}

function sha256_pad($len) {
    $pad = "\x80";
    $z = (56 - (($len + 1) % 64) + 64) % 64;
    $pad .= str_repeat("\x00", $z);
    $bits = $len * 8;
    $hi = intdiv($bits, 0x100000000);
    $lo = $bits & 0xffffffff;
    return $pad . pack('N2', $hi, $lo);
}

function sha256_compress($chunk, $h) {
    static $k = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    $w = array_values(unpack('N16', $chunk));
    for ($i = 16; $i < 64; $i++) {
        $s0 = rotr($w[$i - 15], 7) ^ rotr($w[$i - 15], 18) ^ ($w[$i - 15] >> 3);
        $s1 = rotr($w[$i - 2], 17) ^ rotr($w[$i - 2], 19) ^ ($w[$i - 2] >> 10);
        $w[$i] = u32($w[$i - 16] + $s0 + $w[$i - 7] + $s1);
    }
    [$a,$b,$c,$d,$e,$f,$g,$hh] = $h;
    for ($i = 0; $i < 64; $i++) {
        $s1 = rotr($e, 6) ^ rotr($e, 11) ^ rotr($e, 25);
        $ch = ($e & $f) ^ ((~$e) & $g);
        $t1 = u32($hh + $s1 + $ch + $k[$i] + $w[$i]);
        $s0 = rotr($a, 2) ^ rotr($a, 13) ^ rotr($a, 22);
        $maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
        $t2 = u32($s0 + $maj);
        $hh = $g; $g = $f; $f = $e; $e = u32($d + $t1);
        $d = $c; $c = $b; $b = $a; $a = u32($t1 + $t2);
    }
    return [
        u32($h[0] + $a), u32($h[1] + $b), u32($h[2] + $c), u32($h[3] + $d),
        u32($h[4] + $e), u32($h[5] + $f), u32($h[6] + $g), u32($h[7] + $hh)
    ];
}

function sha256_extend($mac, $processed_len, $append) {
    $h = array_values(unpack('N8', hex2bin($mac)));
    $data = $append . sha256_pad($processed_len + strlen($append));
    for ($i = 0; $i < strlen($data); $i += 64) {
        $h = sha256_compress(substr($data, $i, 64), $h);
    }
    return vsprintf('%08x%08x%08x%08x%08x%08x%08x%08x', $h);
}

$cycle = keeper_talk("CYCLE\n");
$msg = 'cycle=' . $cycle;
$mac = keeper_talk('SIGN ' . bin2hex($msg) . "\n");
$append = '&give_flag';

if (!preg_match('/^[0-9a-f]{64}$/', $mac)) {
    file_put_contents($out, "bad-sign\ncycle=$cycle\nmsg=$msg\nmac=$mac\nkeeper_error=$last_keeper_error\n");
    exit;
}

for ($secret_len = 1; $secret_len <= 64; $secret_len++) {
    $glue = sha256_pad($secret_len + strlen($msg));
    $processed = $secret_len + strlen($msg) + strlen($glue);
    $forged = $msg . $glue . $append;
    $sig = sha256_extend($mac, $processed, $append);
    $reply = keeper_talk('FLAG ' . bin2hex($forged) . ' ' . $sig . "\n");
    if (strpos($reply, 'ERR') !== 0 && $reply !== '') {
        file_put_contents($out, $reply . "\n");
        exit;
    }
}

file_put_contents($out, "failed\ncycle=$cycle\nmac=$mac\n");
