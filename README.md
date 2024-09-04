https://github.com/francisrstokes/githublog/blob/main/2022/6/15/rolling-your-own-crypto-aes.md
https://github.com/francisrstokes/AES-C/tree/main/src
https://loup-vaillant.fr/articles/crypto-is-not-magic
https://de.wikipedia.org/wiki/Advanced_Encryption_Standard
https://www.cryptopals.com/sets/1/challenges/6

AES standard:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

```
openssl aes-128-ecb -d -nosalt -in <(base64 -d 7.txt) -K $(printf '%s' 'YELLOW SUBMARINE' | xxd -c 16 -g 0 -l 16 -ps) > 7.plain.txt

openssl aes-128-ecb -e -nosalt  -in 7.plain.txt -K $(printf '%s' 'YELLOW SUBMARINE' | xxd -c 16 -g 0 -l 16 -ps) | base64 -w 60
```
