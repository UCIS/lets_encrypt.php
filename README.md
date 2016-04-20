lets_encrypt.php
================
This script provides a simple, self-contained ACME client implementation in PHP, primarily written
for use with the [Let's Encrypt Certificate Authority](https://letsencrypt.org/).

The only requirement is a somewhat recent PHP version (5.3.3 has been confirmed to work) with HTTP
stream support and the OpenSSL extension enabled. And maybe some other really standard "extensions".

The script is written to be used on the command line, but can easily be modified for use in other
environments (but do you really want your publicly accessible scripts to handle your SSL keys!?).

Usage
-----
The script supports the following options:

| Option | Argument         | Description |
|--------|------------------|-------------|
| -r     | web root path    | Specifies the web root directory in which the .well-known/acme-challenge/* file structure will be created |
| -d     | domain name      | Specifies a fully qualified domain names for which to request a certificate (use multiple times for multiple domains) |
| -a     | account key file | Specifies the filename of the private account key to use, or where to store a newly generated account key if the file does not exist (optional, a temporary key is used if unspecified) |
| -e     | e-mail address   | Specifies the e-mail address to register as contact for the account key (optional) |
| -c     | certificate bundle file | Specifies where to store the generated certificate bundle in PEM format (key + cert + intermediate), the server key from this file is reused if it exists (optional) |
| -p     |                  | Print the resulting certificate bundle to the standard output (default if -c is not specified) |
| -s     |                  | Use the Let's Encrypt staging server (for testing) |

Example usage:
```text
./lets_encrypt.php -r /var/www -d www.example.com -d example.com -c /etc/apache2/ssl/example.com.pem
```

Credits, contact & fun facts
----------------------------
* Written by Ivo Smits, [UCIS Internet](http://www.ucis.nl) <<Ivo@UCIS.nl>> and released under the Simplified BSD License
* Based on my own [C# ACME client](https://github.com/UCIS/UCIS.Core/blob/master/NaCl/SSLUtils.cs), which in turn is based on the pretty nice [Bash script from Calomel](https://calomel.org/lets_encrypt_client.html).
* I had to generate a CSR from scratch because C#/.Net doesn't support CSR generation at all and PHP's OpenSSL extension does not support alternative subject names. You wouldn't believe how many different RFCs are involved...
