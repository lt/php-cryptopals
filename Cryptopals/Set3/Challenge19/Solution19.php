<?php

/*
 * http://cryptopals.com/sets/3/challenges/19/
 *
 * Break fixed-nonce CTR mode using substitions
 *
 * Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.
 *
 * In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:
 * SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
 * Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
 * RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
 * RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
 * SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
 * T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
 * T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
 * UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
 * QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
 * T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
 * VG8gcGxlYXNlIGEgY29tcGFuaW9u
 * QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
 * QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
 * QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
 * QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
 * QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
 * VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
 * SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
 * SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
 * VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
 * V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
 * V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
 * U2hlIHJvZGUgdG8gaGFycmllcnM/
 * VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
 * QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
 * VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
 * V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
 * SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
 * U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
 * U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
 * VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
 * QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
 * SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
 * VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
 * WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
 * SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
 * SW4gdGhlIGNhc3VhbCBjb21lZHk7
 * SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
 * VHJhbnNmb3JtZWQgdXR0ZXJseTo=
 * QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
 *
 * (This should produce 40 short CTR-encrypted ciphertexts).
 *
 * Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.
 *
 * Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:
 * CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
 *
 * And since the keystream is the same for every ciphertext:
 * CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't say!")
 *
 * Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.
 *
 * Don't overthink it.
 * Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.
 */

require_once '../utils/random-bytes.php';
require_once '18-implement-ctr-the-stream-cipher-mode.php';

$plaintexts = [
    'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
];

$plaintexts = array_map('base64_decode', $plaintexts);
$key = getRandomBytes(16);
$ciphertexts = array_map('encryptAES128CTR', $plaintexts, array_fill(0, 40, $key));

// "Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on."

// if (c1 ^ guess ^ cN) looks reasonable, keep it.

$testKey1 = $ciphertexts[0] ^ 'The';
$testKey2 = $ciphertexts[0] ^ 'Tha';
$testKey3 = $ciphertexts[0] ^ 'Thi';
for ($y = 1; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    $result2 = $ciphertexts[$y] ^ $testKey2;
    $result3 = $ciphertexts[$y] ^ $testKey3;
    print "$y: $result1 $result2 $result3\n";
}

/* Crap deleted
4: The Tha Thi // cipher 4 starts with the same 3 letters as cipher 0
16: I l I h I ` // "I " is a good digram for the start of a line - If cipher 0 starts "I l" or "I h" cipher 16 starts "The" or "Tha"
23: I d I ` I h // "I " is a good digram for the start of a line - If cipher 0 starts "I d" or "I h" cipher 23 starts "The" or "Thi"
25: I d I ` I h // "I " is a good digram for the start of a line - If cipher 0 starts "I d" or "I h" cipher 25 starts "The" or "Thi"
30: I d I ` I h // "I " is a good digram for the start of a line - If cipher 0 starts "I d" or "I h" cipher 30 starts "The" or "Thi"
39: r r r
*/

$testKey1 = $ciphertexts[0] ^ 'I l';
$testKey2 = $ciphertexts[0] ^ 'I h';
$testKey3 = $ciphertexts[0] ^ 'I d';
for ($y = 1; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    $result2 = $ciphertexts[$y] ^ $testKey2;
    $result3 = $ciphertexts[$y] ^ $testKey3;
    print "$y: $result1 $result2 $result3\n";
}

/* "I h" is most sane.
1: Coi Com Coa
2: Frk Fro Frc
3: Eic Eig Eik
4: I l I h I d
5: Or$ Or  Or,
6: Or$ Or  Or,
7: Poh Pol Po`
8: An` And Anh
9: Of$ Of  Of,
10: To$ To  To,
11: Ark Aro Arc
12: Bem Bei Bee
13: Bup But Bux
14: Alh All Al`
15: A p A t A x
16: The Tha Thm
17: In$ In  In,
18: Hev Her He~
19: Unp Unt Unx
20: Whe Wha Whm
21: Wha Whe Whi
22: Sha She Shi
23: Thm Thi The
24: An` And Anh
25: Thm Thi The
26: Waw Was Wa
27: He$ He  He,
28: So$ So  So,
29: So$ So  So,
30: Thm Thi The
31: A ` A d A h
32: He$ He  He,
33: To$ To  To,
34: Yep Yet Yex
35: He( He, He
36: In$ In  In,
37: He( He, He
38: Tre Tra Trm
39: A p A t A x
 */

$testKey1 = $ciphertexts[0] ^ 'I have';
$testKey2 = $ciphertexts[0] ^ 'I hope';
$testKey3 = $ciphertexts[0] ^ 'I hate';
for ($y = 1; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    $result2 = $ciphertexts[$y] ^ $testKey2;
    $result3 = $ciphertexts[$y] ^ $testKey3;
    print "$y: $result1 $result2 $result3\n";
}

/* Looks like "I have"
1: Coming Comghg Comilg
2: From c Froc&c From"c
3: Eighte Eigfre Eighve
4: I have I hope I hate
5: Or pol Or ~il Or pml
6: Or hav Or fgv Or hcv
7: Polite Polgre Polive
8: And th And.rh And vh
9: Of a m Of o&m Of a"m
10: To ple To ~je To pne
11: Around Aro{hd Arould
12: Being  Bei`a  Beine
13: But li But.ji But ni
14: All ch All.eh All ah
15: A terr A tktr A tepr // try "terrible " for +5 "terror " for +3
16: That w Thaz&w That"w
17: In ign In gan In ien
18: Her ni Her.hi Her li
19: Until  Untgj  Untin
20: What v Whaz&v What"v
21: When y Whe`&y When"y
22: She ro She.to She po
23: This m Thi}&m This"m
24: And ro And.to And po
25: This o Thi}&o This"o
26: Was co Was.eo Was ao
27: He mig He cog He mkg
28: So sen So }cn So sgn
29: So dar So jgr So dcr
30: This o Thi}&o This"o
31: A drun A d|sn A drwn
32: He had He fgd He hcd
33: To som To }im To smm
34: Yet I  Yet.O  Yet K
35: He, to He,.ro He, vo
36: In the In zne In tje
37: He, to He,.ro He, vo
38: Transf Tra`uf Tranqf
39: A terr A tktr A tepr

 */

$testKey1 = $ciphertexts[15] ^ 'A terrible ';
$testKey2 = $ciphertexts[15] ^ 'A terror';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    $result2 = $ciphertexts[$y] ^ $testKey2;
    print "$y: $result1   $result2\n";
}

/* Terrible :)
0: I have met    I have&}
1: Coming with   Coming&g
2: From counte   From cie
3: Eighteenth-   Eightec~ // What normally hyphenates "Eighteenth-", "century " ?
4: I have pass   I have&`
5: Or polite m   Or polod
6: Or have lin   Or havc0
7: Polite mean   Polite&}
8: And thought   And thie
9: Of a mockin   Of a mis
10: To please a   To plegc
11: Around the    Around&d
12: Being certa   Being eu // "in " ?
13: But lived w   But lipu
14: All changed   All chg~
15: A terrible    A terror
16: That woman'   That wi}
17: In ignorant   In ignib
18: Her nights    Her niax
19: Until her v   Until nu
20: What voice    What viy
21: When young    When yie
22: She rode to   She robu
23: This man ha   This mg~
24: And rode ou   And robu
25: This other    This orx
26: Was coming    Was coky
27: He might ha   He mignd
28: So sensitiv   So senuy
29: So daring a   So daro~
30: This other    This orx
31: A drunken,    A drunmu
32: He had done   He had&t
33: To some who   To somc0
34: Yet I numbe   Yet I he
35: He, too, ha   He, toi<
36: In the casu   In the&s
37: He, too, ha   He, toi<
38: Transformed   Transfib
39: A terrible    A terror
 */

$testKey1 = $ciphertexts[3] ^ 'Eighteenth-century ';
$testKey2 = $ciphertexts[12] ^ 'Being certain ';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    $result2 = $ciphertexts[$y] ^ $testKey2;
    print "$y: $result1   $result2\n";
}

/* century :)
0: I have met them at    I have met the
1: Coming with vivid f   Coming with vi
2: From counter or des   From counter o
3: Eighteenth-century    Eighteenth-cen
4: I have passed with    I have passed
5: Or polite meaningle   Or polite mean // "ss "
6: Or have lingered aw   Or have linger
7: Polite meaningless    Polite meaning
8: And thought before    And thought be
9: Of a mocking tale o   Of a mocking t
10: To please a compani   To please a co
11: Around the fire at    Around the fir
12: Being certain that    Being certain
13: But lived where mot   But lived wher
14: All changed, change   All changed, c
15: A terrible beauty i   A terrible bea
16: That woman's days w   That woman's d
17: In ignorant good wi   In ignorant go
18: Her nights in argum   Her nights in  // "ent "
19: Until her voice gre   Until her voic
20: What voice more swe   What voice mor
21: When young and beau   When young and // "tiful "
22: She rode to harrier   She rode to ha
23: This man had kept a   This man had k
24: And rode our winged   And rode our w
25: This other his help   This other his
26: Was coming into his   Was coming int
27: He might have won f   He might have
28: So sensitive his na   So sensitive h
29: So daring and sweet   So daring and
30: This other man I ha   This other man
31: A drunken, vain-glo   A drunken, vai
32: He had done most bi   He had done mo
33: To some who are nea   To some who ar
34: Yet I number him in   Yet I number h
35: He, too, has resign   He, too, has r
36: In the casual comed   In the casual
37: He, too, has been c   He, too, has b
38: Transformed utterly   Transformed ut
39: A terrible beauty i   A terrible bea
 */

$testKey1 = $ciphertexts[21] ^ 'When young and beautiful ';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    print "$y: $result1\n";
}

/* beautiful
0: I have met them at close,
1: Coming with vivid faces
2: From counter or desk amob
3: Eighteenth-century house
4: I have passed with a nod,
5: Or polite meaningless wo~
6: Or have lingered awhile m
7: Polite meaningless words
8: And thought before I had,
9: Of a mocking tale or a ge
10: To please a companion
11: Around the fire at the c` // the space on the end is wrong
12: Being certain that they m
13: But lived where motley i
14: All changed, changed utti // "utterly" ?
15: A terrible beauty is borb // "born " ?
16: That woman's days were s|
17: In ignorant good will,
18: Her nights in argument
19: Until her voice grew shre
20: What voice more sweet thm
21: When young and beautiful
22: She rode to harriers?
23: This man had kept a schoc // "school " ?
24: And rode our winged horsi // "horses " ?
25: This other his helper anh
26: Was coming into his forci
27: He might have won fame ib
28: So sensitive his nature 
29: So daring and sweet his x
30: This other man I had drem
31: A drunken, vain-glorious,
32: He had done most bitter {
33: To some who are near my d
34: Yet I number him in the 
35: He, too, has resigned hi
36: In the casual comedy;
37: He, too, has been changeh
38: Transformed utterly:
39: A terrible beauty is borb
 */

$testKey1 = $ciphertexts[14] ^ 'All changed, changed utterly ';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    print "$y: $result1\n";
}

/* utterly
0: I have met them at close of ~ // space on the end likely wrong
1: Coming with vivid faces
2: From counter or desk among gh
3: Eighteenth-century houses.
4: I have passed with a nod of n
5: Or polite meaningless words,
6: Or have lingered awhile and i
7: Polite meaningless words,
8: And thought before I had don
9: Of a mocking tale or a gibe
10: To please a companion
11: Around the fire at the club,
12: Being certain that they and S
13: But lived where motley is woh
14: All changed, changed utterly
15: A terrible beauty is born.
16: That woman's days were spent
17: In ignorant good will,
18: Her nights in argument
19: Until her voice grew shrill.
20: What voice more sweet than h
21: When young and beautiful,
22: She rode to harriers?
23: This man had kept a school
24: And rode our winged horse.
25: This other his helper and frs
26: Was coming into his force;
27: He might have won fame in th
28: So sensitive his nature seem
29: So daring and sweet his thou} "ghts " ?
30: This other man I had dreamed
31: A drunken, vain-glorious loun
32: He had done most bitter wron}
33: To some who are near my hearn
34: Yet I number him in the song!
35: He, too, has resigned his pah
36: In the casual comedy;
37: He, too, has been changed in:
38: Transformed utterly:
39: A terrible beauty is born.
 */

$testKey1 = $ciphertexts[29] ^ 'So daring and sweet his thoughts ';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    print "$y: $result1\n";
}

/* thoughts
0: I have met them at close of day
1: Coming with vivid faces
2: From counter or desk among grey
3: Eighteenth-century houses.
4: I have passed with a nod of the // Looking at cipher 6, this should rhyme, "head" seems suitable
5: Or polite meaningless words,
6: Or have lingered awhile and sai9 // "said"
7: Polite meaningless words,
8: And thought before I had done
9: Of a mocking tale or a gibe
10: To please a companion
11: Around the fire at the club,
12: Being certain that they and I
13: But lived where motley is worn:
14: All changed, changed utterly:
15: A terrible beauty is born.
16: That woman's days were spent
17: In ignorant good will,
18: Her nights in argument
19: Until her voice grew shrill.
20: What voice more sweet than hers
21: When young and beautiful,
22: She rode to harriers?
23: This man had kept a school
24: And rode our winged horse.
25: This other his helper and frien9 // "friend" and "end" for 27
26: Was coming into his force;
27: He might have won fame in the e3 // "end"
28: So sensitive his nature seemed,
29: So daring and sweet his thoughts
30: This other man I had dreamed
31: A drunken, vain-glorious lout.
32: He had done most bitter wrong
33: To some who are near my heart,
34: Yet I number him in the song;
35: He, too, has resigned his part
36: In the casual comedy;
37: He, too, has been changed in hi.
38: Transformed utterly:
39: A terrible beauty is born.
 */

$testKey1 = $ciphertexts[4] ^ 'I have passed with a nod of the head';
for ($y = 0; $y < 40; $y++) {
    $result1 = $ciphertexts[$y] ^ $testKey1;
    print "$y: $result1\n";
}

/*
0: I have met them at close of day
1: Coming with vivid faces
2: From counter or desk among grey
3: Eighteenth-century houses.
4: I have passed with a nod of the head
5: Or polite meaningless words,
6: Or have lingered awhile and said
7: Polite meaningless words,
8: And thought before I had done
9: Of a mocking tale or a gibe
10: To please a companion
11: Around the fire at the club,
12: Being certain that they and I
13: But lived where motley is worn:
14: All changed, changed utterly:
15: A terrible beauty is born.
16: That woman's days were spent
17: In ignorant good will,
18: Her nights in argument
19: Until her voice grew shrill.
20: What voice more sweet than hers
21: When young and beautiful,
22: She rode to harriers?
23: This man had kept a school
24: And rode our winged horse.
25: This other his helper and friend
26: Was coming into his force;
27: He might have won fame in the end,
28: So sensitive his nature seemed,
29: So daring and sweet his thought.
30: This other man I had dreamed
31: A drunken, vain-glorious lout.
32: He had done most bitter wrong
33: To some who are near my heart,
34: Yet I number him in the song;
35: He, too, has resigned his part
36: In the casual comedy;
37: He, too, has been changed in his tur // "turn" I suppose - this is the longest ciphertext, so nothing to verify with
38: Transformed utterly:
39: A terrible beauty is born.
 */

print "\nSorry for the spam, solutions done with guesswork as the challenge instructed.\nThere's plenty of comments in the source explaining what's going on.\n\n";

$finalKeysteam = $ciphertexts[37] ^ 'He, too, has been changed in his turn';

for ($y = 0; $y < 40; $y++) {
    $myPlaintext = $ciphertexts[$y] ^ $finalKeysteam;
    if ($myPlaintext !== $plaintexts[$y]) {
        print "Plaintext $y not properly recovered.\n";
        print "Cracked : $myPlaintext\nOriginal: {$plaintexts[$y]}\n\n";
    }
}