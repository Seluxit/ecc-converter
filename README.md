## Instalation

Clone GIT repository: 

    git clone https://github.com/Seluxit/ecc-converter

Build excutable

    cd build
    ./configure
    make

## Command line switches
    
    -p --private        Private key in HEX string or file name in PEM format
    -b --public         Public key in HEX string or file name ib PEM format
    -g --generate       Generate private public key pair and save to PEM file format.
    -o --output         Output conversion result to specified file name (PEM file format).


## Usage examples: 

Generate secp256r1 elliptic curve's private and public key pair and save to PEM files: 'ecc-gen-private-key.pem' and
ecc-gen-public-key.pem

    ./ecc_converter -g


Save private key (hex string) to PEM file format

    ./ecc_converter -p 2FB63239EFCB58A49DF8A0F582994801C3881D6829873EFE2C63C2191121118E

Save public key (hex string) to PEM file format

    ./ecc_converter -b C6364CD224AC16E6DEB5B97C8F5FB1679F6F940F9C9A648DF5070122267B4338

Make an agreement on secret shared key using PEM files or HEX strings:

    ./ecc_converter -b 'public-key.pem' -p 'private-key.pem' 

or    
    
    ./ecc_converter -b 'public-key.pem' -p 2FB63239EFCB58A49DF8A0F582994801C3881D6829873EFE2C63C2191121118E

or  

    ./ecc_converter -b C6364CD224AC16E6DEB5B97C8F5FB1679F6F940F9C9A648DF5070122267B4338 -p 'private-key.pem'

or

    ./ecc_converter -b C6364CD224AC16E6DEB5B97C8F5FB1679F6F940F9C9A648DF5070122267B4338 -p
    FB63239EFCB58A49DF8A0F582994801C3881D6829873EFE2C63C2191121118E

