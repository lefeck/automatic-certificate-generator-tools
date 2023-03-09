# automatic-certificate-generator-tools
This is a self-issuing certificate tool that makes it very easy to issue certificates.

## Requirements

Tested on a host running Linux System

Utilities required:
> openssl

## Usage
```shell
[root@localhost ~]# ./automatic-certificate-generator-tools.sh  -h
Usage: test.sh [-a [rsa|ecc]] [-d <domain>] [-n <name>] [-t <days>] [-h] [-v]"

💁 This script will be automatic certificate genetatory.


Available options:

-a --algorithm         Algorithms supported by the issuing certificate tool. for example: rsa, ecc, default the algorithm is rsa.
-d --domain            The name of the domain name required to issue the certificate. for example: xxx.com, abc.org, *.abc.org, default the domain name is "domain.com".
-n --name              Name of the file generated by the issuance certificate, default the name is server.
-t --days              Set the expiration time of the certificate, default the value is 3650 days.
-h --help              Print this help and exit
-v --verbose           Print script debug info
```

```shell
[root@localhost ~]# ./automatic-certificate-generator-tools.sh -a ecc -t 365000
[2023-03-09 13:27:55] 📁 Created temporary working directory /tmp/tmp.VRlWStEAiV
[2023-03-09 13:27:55] 👍 generate ca certificate file
[2023-03-09 13:27:55] 👍 generate ca certificate file.
[2023-03-09 13:27:55] 👍 generate server key and crt file
[2023-03-09 13:27:55] 👍 genetate server key file
[2023-03-09 13:27:55] 👍 genetate server certificate issuance request file
[2023-03-09 13:27:55] 👍 genetate server certificate file
[2023-03-09 13:27:55] 👍 genetate server fullchain file
Enter Export Password:
Verifying - Enter Export Password:
[2023-03-09 13:28:02] 👍 certificate format convert CRT to P12
[2023-03-09 13:28:02] 👍 certificate format convert CRT to PEM
[2023-03-09 13:28:02] 👍 certificate format convert PEM to DER
[2023-03-09 13:28:02] 👍 all of the files generated in the /tmp/tmp.VRlWStEAiV directory
[2023-03-09 13:28:02] ✅ Completed.
``` 

## Thanks


The script is implemented with reference to the blog [openssl-self-signed-cert](https://www.baeldung.com/openssl-self-signed-cert), and so on.
If you have any questions, you can send me an email, and I will do my best to solve it.


## License

MIT license.