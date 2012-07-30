<?php

require_once("OAuthConsumer.php");

$end_point = 'http://term.ie/oauth/example';
$params = array('file'=>'vacation.jpg', 'size'=>'original');
$method = 'POST';
$consumer_key = new OAuthKey('key','secret');
$token = new OAuthKey('access-key','access_secret');

echo "<h1>OAuth 1.0 Consumer (RFC 5849)</h1>";
echo "<p>Uses OAuth test server at http://term.ie/oauth/example/index.php</p>";
echo "End Point: $end_point<br />";
echo "Method: $method<br />";
echo "Consumer Key: $consumer_key->key<br />";
echo "Consumer Secret: $consumer_key->secret<br />";
echo "Params: "; var_dump($params); echo "<br />";
echo "Token: "; var_dump($token); echo "<br />";
echo "<hr />";

###############################################################################
# PLAINTEXT EXAMPLE
###############################################################################

echo "<h2>Plaintext Example</h2>";

$signer = new OAuthSignMethod_Plaintext();
$consumer = new OAuthConsumer($consumer_key,$signer);

echo "<h3>Get Request Token</h3>";

$request = $consumer->request($method,"$end_point/request_token.php",$params,null);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: "; var_dump($response->data()); echo "<br />";
echo "Type: ".$response->type()."<br />";

// parse out request token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Get Access Token</h3>";

$request = $consumer->request($method,"$end_point/access_token.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

// parse out access token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Authenticated Call</h3>";

$request = $consumer->request($method,"$end_point/echo_api.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

echo "<h3>Sanity Check</h3>";

echo "<p>If everything went well, then the provider should have returned the same params that we sent.</p>";

$original = OAuthHelper::http_prepare($params);
echo "Original Params: ".$original."<br />";
echo "Returned Params: ".$response->data()."<br />";

if ($original == $response->data()) echo "Success!";
else echo "Not the same! That's a problem.";

echo "<hr />";

###############################################################################
# HMAC-SHA1 EXAMPLE
###############################################################################

echo "<h2>HMAC-SHA1 Example</h2>";

$signer = new OAuthSignMethod_HMAC_SHA1();
$consumer = new OAuthConsumer($consumer_key,$signer);

echo "<h3>Get Request Token</h3>";

$request = $consumer->request($method,"$end_point/request_token.php",$params,null);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

// parse out request token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Get Access Token</h3>";

$request = $consumer->request($method,"$end_point/access_token.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

// parse out access token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Authenticated Call</h3>";

$request = $consumer->request($method,"$end_point/echo_api.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

echo "<h3>Sanity Check</h3>";

echo "<p>If everything went well, then the provider should have returned the same params that we sent.</p>";

$original = OAuthHelper::http_prepare($params);
echo "Original Params: ".$original."<br />";
echo "Returned Params: ".$response->data()."<br />";

if ($original == $response->data()) echo "Success!";
else echo "Not the same! That's a problem.";

echo "<hr />";

###############################################################################
# RSA-SHA1 EXAMPLE
###############################################################################

echo "<h2>RSA-SHA1 Example</h2>";

$private_cert = 
'-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----';
$signer = new OAuthSignMethod_RSA_SHA1();
$signer->set_private_cert($private_cert);
$consumer = new OAuthConsumer($consumer_key,$signer);

echo "<h3>Get Request Token</h3>";

$request = $consumer->request($method,"$end_point/request_token.php",$params,null);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

// parse out request token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Get Access Token</h3>";

$request = $consumer->request($method,"$end_point/access_token.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

// parse out access token
$result = OAuthHelper::param_decode($response->data());
$token = new OAuthKey($result['oauth_token'],$result['oauth_token_secret']);

echo "<h3>Authenticated Call</h3>";

$request = $consumer->request($method,"$end_point/echo_api.php",$params,$token);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

echo "<h3>Sanity Check</h3>";

echo "<p>If everything went well, then the provider should have returned the same params that we sent.</p>";

$original = OAuthHelper::http_prepare($params);
echo "Original Params: ".$original."<br />";
echo "Returned Params: ".$response->data()."<br />";

if ($original == $response->data()) echo "Success!";
else echo "Not the same! That's a problem.";

echo "<hr />";


/*
HMAC-SHA1 TEST VALUES
===========
URL: http://photos.example.net/photos
PARAMS: 'file'=>'vacation.jpg','size'=>'original'
SIGNER: HMAC-SHA1
CONSUMER KEY: dpf43f3p2l4k3l03
CONSUMER SECRET: kd94hf93k423kf44
TOKEN KEY: nnch734d00sl2jdk
TOKEN SECRET: pfkkdhi9sl3r4s00

BASE: GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal
KEY: kd94hf93k423kf44&pfkkdhi9sl3r4s00
SIGNATURE: tR3+Ty81lMeYAr/Fid0kMTYa/WM=

*/