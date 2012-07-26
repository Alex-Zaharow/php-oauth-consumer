<?php

require_once("OAuth.php");

$consumer = new OAuthConsumer('key','secret');
//$consumer = new OAuthConsumer('dpf43f3p2l4k3l03','kd94hf93k423kf44');
$params = array();

//$token = new OAuthToken('nnch734d00sl2jdk','pfkkdhi9sl3r4s00');

$request = $consumer->request('POST','http://term.ie/oauth/example/request_token.php',$params,null);
//$params = array('file'=>'vacation.jpg','size'=>'original');
//$request = $consumer->request('GET','http://photos.example.net/photos',$params,$token);
$signer = new OAuthSignMethod_HMAC_SHA1($consumer);
$request->sign($signer);
$response = $request->send();

echo "Status: ".$response->code()."<br />";
echo "Header: ",$response->header()."<br />";
echo "Data: ".$response->data()."<br />";
echo "Type: ".$response->type()."<br />";

echo "DONE";

/*
TEST VALUES
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
SIG: tR3+Ty81lMeYAr/Fid0kMTYa/WM=

*/