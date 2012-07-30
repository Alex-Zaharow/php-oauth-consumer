PHP OAuth Consumer
==================

Implementation of a OAuth 1.0 (RFC 5849) compliant consumer.
https://tools.ietf.org/html/rfc5849

Features
--------

- OAuth 1.0 compliant.
- Supports Plaintext, HMAC-SHA1, and RSA-SHA1 signatures.
- Supports custom user implimented signers.
- Includes a simple sender class for communication with the Provider so that
  you can start working right away.
- Supports custom user implimented sender.
- Supports two-legged OAuth with no additional code.

Requirements
------------

- PHP 5.3 and above.
- PHP curl support (unless using your own sender).
- PHP openssl support.

Usage
-----

The OAuthConsumer is easy to use for two legged OAuth calls. To support three
legged OAuth calls, you simply need to impliment a callback function in your 
own code to obtain access and request tokens from the provider.

```php
<?php
$consumer_key = '123456';
$consumer_secret = 'abcdefghijklmnop';
$consumer_key = new OAuthKey($consumer_key,$consumer_secret);

// Provide a signing method to use when sending requests. You can use Plaintext,
// HMAC-SHA1, RSA-SHA1, or any other method the Provider supports that you 
// impliment.
$cert = '-----START PRIVATE KEY-----gaAnkjpS9803lkn....-----END PRIVATE KEY-----';
// For RSA-SHA1, you must provide a private certificate for encryption.
// This parameter should not be provided for HMAC-SHA1 or Plaintext.
$signer = new OAuthSignMethod_RSA_SHA1($cert);

// Create a new consumer object.
$consumer = new OAuthConsumer($consumer_key,$signer);
// Prepare the params you want to pass to the server.
$params = array(
	'file' => 'picture.jpg',
	'size' => '1000'
);

// If you already have an access or request token, pass it as well otherwise, 
// just pass null.
$token = null;
$token = new OAuthToken('access_token','access_token_secret');
// Generate a new OAuth request. Supported methods include GET and POST.
// You can add support for additional HTTP methods by creating your own or
// extending the default sender.
$consumer->request('GET','http://example.com/oauth',$params,$token)

// Now that the request has been created, it can be sent. Signing is handled
// automatically by the consumer.
$response = $request->send();

// Send returns an OAuthResponse object that allows you to read the http code,
// headers, and data that were returned by the OAuth Provider.
echo $request->code();
echo $request->data();
?>
```

Extending
---------

OAuthConsumer allows the user to extend/replace two classes - the sender and 
the signer.

The sender is the class that OAuthConsumer uses to communicate with the OAuth
server. A basic curl based one is provided and used by default. To replace with
your own, simply create a new class that implements the OAuthSender interface
and pass it to the consumer.

```php
<?php
// ...
class MySender implements OAuthSender
{
	// my code
}
$sender = new MySender();
$consumer = new OAuthConsumer($consumer_key,$signer,$sender);
?>
```

The signer generates the oauth_signature parameter and secures communication
with the OAuth Server. The three main 1.0 spec methods are provided, but you 
can use your own by extending the OAuthSignMethod class.

```php
<?php
class MySigner extends OAuthSignMethod
{
	// my code
}
$signer = new MySigner($consumer);
$consumer = new OAuthConsumer($consumer_key,$signer);
$consumer->request('GET','http://example.com/oauth',$params,null);
?>
```

Legal
-----

Copyright (c) 2012, Matt Colf

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.