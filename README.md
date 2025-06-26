## TOTP Generator

Generate time-based one time passcodes in the command line.

Followup to my [rust based TOTP generator](https://github.com/ryansereno/rust-TOTP)

Based on the [RFC 6238 Standard](https://www.rfc-editor.org/rfc/rfc6238#page-9)

### Usage

```bash
gcc -o totp main.c -lssl -lcrypto
```
```bash
./totp
```

You will be prompted to enter your secret key;
This should be a base32 encoded key (the code that would normally be entered into Authy/ Google Auth App) from your chosen account.

#### If OpenSSL headers are missing:
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS 
brew install openssl
```


