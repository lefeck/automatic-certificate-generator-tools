# automatic-certificate-generator-tools
This is a self-issuing certificate tool that makes it very easy to issue certificates, All certificate formats can be generated.

## Requirements

The script  running Linux System

Utilities required:
> openssl

## Usage
```shell
[root@localhost ~]# ./automatic-certificate-generator-tools.sh  -h
Usage: automatic-certificate-generator-tools.sh [-a [rsa|ecc]] [-f <domain>] [-t <days>] [-p <password>] [-s <show>] [-l <length>] [-C <country>] [-S <state>]  [-L <local>] [-O <organization>] [-o <organizational_unit>]  [-N <common_name>] [-e <ec_name>] [-r <rsa_key_length>] [-h] [-v]

💁 This script will automatically generate certificates.

Available options:

-a, --algorithm         Algorithms supported by the issuing certificate tool. for example: rsa, ecc, default the algorithm is "rsa".
-f, --fqdn              Set the domain name for the certificate, default is "www.pocdomain.com".
-t, --days              Set the expiration time of the certificate, default is 3650 days.
-p, --password          Set password for the service certificate, default is a random string.
-s, --show              Whether to display the service certificate password in the foreground. By default, it will write to a .password file.
-l, --length            Set the length of the password, default is 8 characters. This parameter and the -p option cannot be used together.
-C, --country           Set the country for the certificate, default is "CN".
-S, --state             Set the state for the certificate, default is "ShangHai".
-L, --local             Set the locality for the certificate, default is "ShangHai".
-O, --organization      Set the organization for the certificate, default is "Personal".
-o, --organizational-unit Set the organizational unit for the certificate, default is "IT Department".
-N, --common-name       Set the common name for the certificate, default is "MY CA".
-e, --ec-name           Specifies the elliptic curve (EC) name for the certificate, such as secp256k1, secp384r1, secp521r1, or prime256v1. The default is secp256k1.
-r, --rsa-key-length    Specifies the length of the RSA key for the certificate, in bits. Supported key lengths include 1024, 2048 (default), 3072, and 4096 bits.
                        Other lengths, such as 1536 or 8192 bits, may be available but are less common due to performance considerations.
-h, --help              Print this help and exit.
-v, --verbose           Print script debug info.
```
## example
You need to specify different parameters, the execution process requires you to enter the certificate password to encrypt the certificate. 
```shell
[root@localhost ~]# ./automatic-certificate-generator-tools.sh  -f www.fjptod.com  -a rsa -r 4096
[2024-10-29 14:40:00] 👶 Starting up...
[2024-10-29 14:40:00] 📁 Created temporary working directory /tmp/tmp.IcwAM5ryKn
[2024-10-29 14:40:01] 👍 Generated an RSA private CA key file
[2024-10-29 14:40:01] 👍 Generated CA certificate file
[2024-10-29 14:40:03] 👍 Generated an RSA private server key file
[2024-10-29 14:40:03] 👍 Generated server CSR (Certificate Signing Request) file
[2024-10-29 14:40:03] 👍 Generating x509 v3 extension file
[2024-10-29 14:40:03] 👍 Generated server certificate file
[2024-10-29 14:40:03] 👍 Generated server fullchain file
[2024-10-29 14:40:03] 👍 Certificate format converted to P12
[2024-10-29 14:40:03] 👍 Certificate format converted to PEM
[2024-10-29 14:40:03] 👍 Certificate format converted to DER
[2024-10-29 14:40:03] 👍 Certificate format converted to PFX
[2024-10-29 14:40:03] 👍 The certificate password is in /tmp/tmp.IcwAM5ryKn/.password file
[2024-10-29 14:40:03] ✅ Completed.
``` 
This method is recommended, because it can hide secrets.


The default servver certificate password will not be displayed in the foreground, if you want to display the output, you need to specify the -s parameter. for example:

```shell
[root@localhost ~]# ./automatic-certificate-generator-tools.sh  -f www.poctest.com  -a rsa -r 4096  -s
[2024-10-29 14:41:40] 👶 Starting up...
[2024-10-29 14:41:40] 📁 Created temporary working directory /tmp/tmp.Ypu0O0VYTX
[2024-10-29 14:41:43] 👍 Generated an RSA private CA key file
[2024-10-29 14:41:43] 👍 Generated CA certificate file
[2024-10-29 14:41:44] 👍 Generated Generate an RSA private server key file
[2024-10-29 14:41:44] 👍 Generated server CSR (Certificate Signing Request) file
[2024-10-29 14:41:44] 👍 Generating x509 v3 extension file
[2024-10-29 14:41:44] 👍 Generated server certificate file
[2024-10-29 14:41:44] 👍 Generated server fullchain file
[2024-10-29 14:41:44] 👍 Certificate format converted to P12
[2024-10-29 14:41:45] 👍 Certificate format converted to PEM
[2024-10-29 14:41:45] 👍 Certificate format converted to DER
[2024-10-29 14:41:45] 👍 Certificate format converted to PFX
[2024-10-29 14:41:45] 👍 The certificate server password is sLAzQ32L
[2024-10-29 14:41:45] ✅ Completed.
```

## Thanks

The script is implemented with reference to the blog [openssl-self-signed-cert](https://www.baeldung.com/openssl-self-signed-cert), and so on.
If you have any questions, you can send me an email, and I will do my best to solve it.


## License

MIT license.