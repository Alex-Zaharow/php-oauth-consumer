<?php

// spec: http://oauth.net/core/1.0/
// ideas: https://github.com/juampy72/OAuth-PHP/blob/master/OAuth.php

/*
*	$consumer = new OAuthConsumer(KEY,SECRET);
*	$params = array();
*	$request = $consumer->request('GET','http://foo.com/oauth',$params,TOKEN);
*	$signer = new OAuthSignMethod_Plaintext($consumer);
*	$request->sign($signer);
*	$response = $request->send();
*	if ( $response->status() == 'ok' )
*		$output = $response->raw();
*	else die();
*/

class OAuthConsumer
{
	protected $sender;
	public $consumer_key;
	public $consumer_secret;

	public function __construct($key, $secret, $sender = null)
	{
		$this->consumer_key = $key;
		$this->consumer_secret = $secret;
		// allow custom http handler
		if ($sender == null) $this->sender = new OAuthCurl();
		else $this->sender = $sender;

	}
	public function request($url, $method, $params, OAuthToken $token)
	{
		return new OAuthRequest($this, $this->sender, $url, $method, $params, $token);
	}
}

/**
*	Storage class for access and request tokens.
*/

class OAuthToken
{
	protected $key;
	protected $secret;

	public function __construct($key,$secret)
	{
		$this->key = $key;
		$this->secret = $secret;
	}

	public function serialize()
	{
		$key = OAuthHelper::url_encode($this->key);
		$secret = OAuthHelper::url_encode($this->secret);
		return "oauth_token=$key&oauth_token_secret=$secret";
	}

}

class OAuthRequest
{
	protected $consumer;
	protected $sender;
	protected $url;
	protected $method;
	protected $params;
	protected $token;

	public function __construct($consumer, $sender, $url, $method = 'GET', $params = array(), OAuthToken $token)
	{
		$this->consumer = $consumer;
		$this->sender = $sender;
		$this->url = $url;
		$this->method = $method;
		$this->params = $params;
		$this->token = $token;
	}

	public function sign(OAuthSignMethod $signer)
	{
		$this->params['oauth_signature'] = $signer->generate($this->method,$this->url,$this->params,$this->token);
	}

	public function send()
	{
		// check for signiture
		if (!isset($this->params['oauth_signature']))
		{
			// default to plaintext
			$signer = new OAuthSignMethod_Plaintext($this->consumer);
			$this->sign($signer);
		}

		$output = $this->sender->request($this->url,$this->method,$this->params,null);
		return new OAuthResponse($output);
	}

}

/**
*	Base Signing Method
*
*	Section 9:
*	All Token requests and Protected Resources requests MUST be signed by the
*	Consumer and verified by the Service Provider. The purpose of signing 
*	requests is to prevent unauthorized parties from using the Consumer Key and 
*	Tokens when making Token requests or Protected Resources requests. The 
*	signature process encodes the Consumer Secret and Token Secret into a 
*	verifiable value which is included with the request.
*
*/

abstract class OAuthSignMethod
{
	protected $name = '';
	protected $consumer;

	public function name()
	{
		return $this->name;
	}

	public function __construct(OAuthConsumer $consumer)
	{
		$this->consumer = $consumer;
	}

	abstract public function generate($method,$url,$params,$token = null);

	/**
	*	Construct the signiture base string according to OAuth 1.0 Section 9.1.3.
	*
	*	@param string $method The request method, uppercase
	*	@param string $url The request url
	*	@param array $params An array of request params.
	*	@return string The formatted signiture base string.
	*/

	protected function signature_base_string($method,$url,$params)
	{
		$base = array(
			$this->normalize_http_method($method),
			$this->normalize_http_url($url),
			$this->normalize_http_params($params)
		);
		return OAuthHelper::url_encode($base);
	}

	/**
	*	Normalize the HTTP method according to OAuth 1.0 Section 9.1.3 #1.
	*
	*	@return string The formateed method.
	*/

	protected function normalize_http_method($method)
	{
		// Section 9.1.3 #1: The request method must be uppercase.
		return strtoupper($method);
	}

	/**
	*	Normalize the HTTP url according to OAuth 1.0 Section 9.1.2.
	*
	*	@return string The formatted url.
	*/

	protected function normalize_http_url($url)
	{
		$parts = parse_url($url);

		// Section 9.1.2: The url scheme and host must be lowercase and include the port number.
		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : 80);
		$host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		// Section 9.1.2: The default ports for HTTP (80) and HTTPS (443) must not be included.
		if (($scheme == 'http' and $port != '80') or ($scheme == 'https' and $port != '443'))
		{
			$host = "$host:$port";
		}

		return "$scheme://$host$path";
	}

	/**
	*	Normalize the parameters according to OAuth 1.0 Section 9.1.1.
	*
	*	@return string The formatted parameters.
	*/

	protected function normalize_http_params($params)
	{
		// Section 9.1.1: Exclude oauth_signature
		if (isset($params['oauth_signature'])) unset($params['oauth_signature']);

		return OAuthHelper::http_prepare($params);
	}

}

/**
*	Signing Method: HMAC SHA1
*
*	Section 9.2:
*	The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as
*	defined in [RFC2104] where the Signature Base String is the text and the 
*	key is the concatenated values (each first encoded per Parameter Encoding) 
*	of the Consumer Secret and Token Secret, separated by an ‘&’ character 
*	(ASCII code 38) even if empty.
*
*/

class OAuthSignMethod_HMAC_SHA1 extends OAuthSignMethod
{
	protected $name = 'HMAC_SHA1';

	public function generate($method,$url,$params,$token = null)
	{
		$base_string = $this->signature_base_string($method,$url,$params);

		$parts = array(
			$consumer->secret,
			($token) $token->secret : '';
		);
		$parts = OAuthHelper::url_encode($parts);
		$key = implode('&',$parts);

		// Section 9.2: HMAC Hash using base_string as text and concatenated
		// consumer secret and token secret as the key.
		$hash = hash_hmac('sha1', $base_string, $key, true);
		// Section 9.2.1: Signature is base64 encoded.
		return base64_encode($hash);
	}

}

/**
*	Signing Method: RSA SHA1
*
*	Section 9.3:
*	The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature 
*	algorithm as defined in [RFC3447] section 8.2 (more simply known as 
*	PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5. It is 
*	assumed that the Consumer has provided its RSA public key in a verified way
*	to the Service Provider, in a manner which is beyond the scope of this 
*	specification.
*
*/

class OAuthSignMethod_RSA_SHA1 extends OAuthSignMethod
{
	protected $name = 'RSA_SHA1';

	public function generate($method,$url,$params,$token = null)
	{
		
	}
}

/**
*	Signing Method: Plaintext
*
*	Section 9.4:
*	The PLAINTEXT method does not provide any security protection and SHOULD 
*	only be used over a secure channel such as HTTPS. It does not use the 
*	Signature Base String.
*/

class OAuthSignMethod_Plaintext extends OAuthSignMethod
{
	protected $name = 'PLAINTEXT';

	/**
	*	Generate a plaintext signature per OAuth 1.0 Section 9.4.1.
	*
	*	@param string $method The HTTP request method.
	*	@param string $url The HTTP request URL.
	* 	@param array $params An array of params.
	*	@param OAuthToken $token The access/request token to sign with. 
	*	@return string The signiture.
	*/

	public function generate($method,$url,$params,$token = null)
	{
		$parts = array(
			$this->consumer->secret,
			($token) ? $token->secret : ''
		);
		$parts = OAuthHelper::url_encode($parts);
		$key = implode('&',$parts);

		return $key;
	}
}


class OAuthResponse
{
	public function __construct($output);
	public function status();
	public function raw();
	public function parse()
	{
		//  atom, xml, json, etc.
	}
}

/**
*	Generic wrapper interface used to transmit OAuth data over HTTP.
*/

interface OAuthSender
{
	/**
	*	Send a new HTTP request.
	*
	*	@param string $url The url to transport to.
	*	@param string $method The method to use ('GET', 'POST', etc.)
	*	@param array $params The parameters to send.
	*	@param array $headers The headers to include when sending.
	*	@return string The request output including response headers.
	*/

	public function request($url,$method,$params,$headers);

	/**
	*	Check if an error occured during transport.
	*
	*	@return string Error description, empty on noerror.
	*/

	public function error();
}

/**
*	A simple curl based HTTP transport class for use by OAuth.
*
*	This will be used by default, but can be replaced by any user defined
*	class that implements the OAuthSender interface.
*/

class OAuthCurl implements OAuthSender
{
	protected $ch;

	public function __construct()
	{
		$this->ch = curl_init();
	}

	public function __destruct()
	{
		curl_close($this->ch);
	}

	/**
	*	Send a new HTTP request.
	*
	*	@param string $url The url to transport to.
	*	@param string $method The method to use ('GET', 'POST', etc.)
	*	@param array $params The parameters to send.
	*	@param array $headers The headers to include when sending.
	*	@return string The request output including response headers.
	*/

	public function request($url,$method,$params,$headers)
	{
		$options = array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HEADER => true,
			CURLOPT_CONNECTTIMEOUT = 10,
			CURLOPT_TIMEOUT = 15
		);
		$param_string = OAuthHelper:http_prepare($params);

		switch($this->method)
		{
			case "PUT":
				$options["CURLOPT_URL"] = $url;
				$options["CURLOPT_CUSTOMREQUEST"] = "PUT";
				$options["CURLOPT_POSTFIELDS"] = $param_string;
				break;
			case "DELETE":
				$options["CURLOPT_URL"] = "$url?$param_string";
				$options["CURLOPT_CUSTOMREQUEST"] = "DELETE";
			case "POST":
				$options["CURLOPT_URL"] = $url;
				$options["CURLOPT_POST"] = true;
				$options["CURLOPT_POSTFIELDS"] = $param_string;
				break;
			default:
				$options["CURLOPT_URL"] = "$url?$param_string";
				$options["CURLOPT_HTTPGET"] = true;
		}
		curl_setopt_array($this->ch,$options);

		return curl_exec($this->ch);
	}

	/**
	*	Check if an error occured during transport.
	*
	*	@return string Error description, empty on noerror.
	*/

	public function error()
	{
		if ($error = curl_error($this->ch))
		{
			return curl_errno.': '.$error;
		}
		else return '';
	}

}

/**
*	Additional functions required by OAuth.
*
*	All methods should be static.
*/

class OAuthHelper
{
	/**
	*	Encode values for HTTP url transport per rfc3986.
	*
	*	@param varies The value or array to be encoded.
	*	@return string The rfc3986 encoded value or array.
	*/

	static public function url_encode($input)
	{
		if (is_array($input))
		{
			$result = array();
			foreach($input as $item)
			{
				$result[] = OAuthHelper::url_encode($item);
			}
			return $result;
		}
		else if (is_scalar($input))
		{
			$input = rawurlencode($input);
			return str_replace('+',' ',str_replace('%7e','~',$input));
		}
		else return '';
	}

	/**
	*	Prepare HTTP query parameters per OAuth 1.0 Section 9.1 methods.
	*
	*	@param array $input The parameter key=>value array.
	*	@return string The formatted and serilaized parameters.
	*/

	static public function http_prepare($input)
	{
		if ( !$input || !is_array($input)) return '';

		// url encode keys and values
		$keys = OAuthHelper::url_encode(array_keys($input));
		$values = OAuthHelper::url_encode(array_values($input));
		$params = array_combine($keys,$values);

		// Section 9.1.1 #1: Sort parameters by key name.
		uksort($params,'strcmp');

		$output = array();
		foreach($params as $key => $value)
		{
			if (is_array($value))
			{
				// Section 9.1.1 #1: Sort by value if key names are the same.
				sort($value,SORT_STRING);
				foreach($value as $single)
				{
					$output[] = "$key=$single";
				}
			}
			// Section 9.1.1 #2: Seperate keys and values by '='
			else $output[] = "$key=$value";
		}

		// Section 9.1.1 #2: Seperate key entries by '&'
		return implode('&',$output);
	}

}


/////////////////////////////////////////////////

class OAuthException extends Exception
{

}

///////////////////////////////
