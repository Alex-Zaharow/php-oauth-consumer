<?php

/*
*	Compliant with OAuth 1.0 Spec (RFC 5849)
*	https://tools.ietf.org/html/rfc5849
*/

###############################################################################
#	
#	OAUTH CONSUMER
#	The main interface objects for the OAuth Consumer.
#
###############################################################################

/**
*	OAuth Consumer Object
*/

class OAuthConsumer
{
	protected $sender;
	protected $signer;
	protected $key;

	public function __construct(OAuthKey $key, OAuthSignMethod $signer, $sender = null)
	{
		$this->key = $key;
		$this->signer = $signer;
		// allow custom http handler
		if ($sender == null) $this->sender = new OAuthCurl();
		else $this->sender = $sender;
	}

	public function request($method, $url, $params, OAuthKey $token = null)
	{
		$request = new OAuthRequest($this->key, $this->sender, $method, $url, $params, $token);
		$request->sign($this->signer);
		return $request;
	}
}


/**
*	OAuth Request Object
*/

class OAuthRequest
{
	protected $version = '1.0';

	protected $consumer_key;
	protected $signer;
	protected $sender;
	protected $method;
	protected $url;
	protected $params;
	protected $token;

	/**
	*	Generate a new OAuth request
	*
	*
	*	@param OAuthKey $consumer_key The consumer key.
	*	@param OAuthSender $sender The HTTP transport object.
	*	@param string $method The HTTP request method (POST, GET, etc.)
	*	@param string $url The OAuth server endpoint to contact.
	*	@param array $params The request params to send.
	*	@param OAuthKey The OAuth token to pass. (optional)
	*/

	public function __construct($consumer_key, $sender, $method = 'GET', $url, $params = array(), OAuthKey $token = null)
	{
		$this->consumer_key = $consumer_key;
		$this->sender = $sender;
		$this->method = $method;
		$this->url = $url;
		$this->token = $token;

		// prepare params
		$base_params = array(
			"oauth_version" => $this->version,
			"oauth_timestamp" => $this->generate_timestamp(),
			"oauth_nonce" => $this->generate_nonce(),
			"oauth_consumer_key" => $this->consumer_key->key
		);

		// add token
		if ($token) $base_params["oauth_token"] = $token->key;

		// add url encoded params
		$url_params = OAuthHelper::param_decode(parse_url($url,PHP_URL_QUERY));

		$this->params = array_filter(array_merge($base_params, $url_params, $params));
	}

	/**
	*	Generate an OAuth signature and add it to the request.
	*
	*	@return void
	*/

	public function sign($signer)
	{
		$this->params['oauth_signature_method'] = $signer->name();
		$signature = $signer->generate($this->method, $this->url, $this->params, $this->consumer_key->secret, $this->token);
		$this->params['oauth_signature'] = $signature;
	}

	/**
	*	Prepare and send an OAuth request.
	*
	*	@return OAuthResponse
	*/

	public function send()
	{
		// prepare parameters
		$url = OAuthHelper::url_format($this->url);
		$params = OAuthHelper::http_prepare($this->params);
		$header = $this->generate_header();

		return $this->sender->request($this->method, $url, $params, $header);
	}

	/**
	*	Generate the OAuth nonce, a random one time use token.
	*
	*	@return string The nonce.
	*/

	protected function generate_nonce()
	{
		$rand = mt_rand();
		$time = microtime();
		return md5($rand.$time);
	}

	/**
	*	Generate OAuth timestamp.
	*
	*	@return int The current UNIX timestamp.
	*/

	protected function generate_timestamp()
	{
		return time();
	}

	/**
	*	Generate OAuth authorization header
	*
	*	@param string $realm The authentication realm.
	*	@return string The header.
	*/

	protected function generate_header($realm = null)
	{
		$headers = array();

		if ($realm) $headers[] = 'Authorization: OAuth realm="'.OAuthHelper::url_encode($realm).'"';
		else $headers[] = 'Authorization: OAuth ';

		foreach ($this->params as $key => $value)
		{
			if (substr($key,0,5) == "oauth")
			{
				if (is_array($value))
				{
					throw new OAuthException("Arrays are not supported in headers.");
				}
				$headers[] = OAuthHelper::url_encode($key)."=".OAuthHelper::url_encode($value);
			}
		}

		return implode(',',$headers);
	}
}

/**
*	OAuth Response Handler Object
*
*	Not much to see here.
*/

class OAuthResponse
{
	protected $raw;
	protected $code;
	protected $header;
	protected $data;

	public function __construct($raw,$code,$header,$data,$type)
	{
		$thos->raw = $raw;
		$this->code = $code;
		$this->header = $header;
		$this->data = $data;
		$this->type = $type;
	}

	public function raw()
	{
		return $this->raw;
	}

	public function code()
	{
		return $this->code;
	}

	public function header()
	{
		return $this->header;
	}

	public function data()
	{
		return $this->data;
	}

	public function type()
	{
		return $this->type;
	}
}

###############################################################################
#	
#	OAUTH SIGNATURE CREATION
#	Handles the oauth_signature parameter.
#
#	1) HMAC SHA1
#	2) RSA SHA1
#	3) Plaintext
#
###############################################################################

/**
*	OAuth Base Signing Method
*/

abstract class OAuthSignMethod
{
	protected $name = '';

	public function name()
	{
		return $this->name;
	}

	abstract public function generate($method, $url, $params, $consumer_secret, $token = null);

	/**
	*	Construct the signiture base string according to OAuth 1.0 Section 9.1.3.
	*
	*	@param string $method The request method
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
		return implode('&',OAuthHelper::url_encode($base));
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
		return OAuthHelper::url_format($url);
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
*	OAuth Signing Method: HMAC SHA1
*/

class OAuthSignMethod_HMAC_SHA1 extends OAuthSignMethod
{
	protected $name = 'HMAC-SHA1';

	public function generate($method, $url, $params, $consumer_secret, $token = null)
	{
		$base_string = $this->signature_base_string($method,$url,$params);

		$parts = array(
			$consumer_secret,
			($token) ? $token->secret : ''
		);
		$key = implode('&',OAuthHelper::url_encode($parts));

		// Section 9.2: HMAC Hash using base_string as text and concatenated
		// consumer secret and token secret as the key.
		$hash = hash_hmac('sha1', $base_string, $key, true);
		// Section 9.2.1: Signature is base64 encoded.
		return base64_encode($hash);
	}

}

/**
*	OAuth Signing Method: RSA SHA1
*/

class OAuthSignMethod_RSA_SHA1 extends OAuthSignMethod
{
	protected $name = 'RSA-SHA1';
	protected $private_cert = null;
	protected $private_cert_passphrase = "";

	/**
	*	@param string $cert Either a PEM formatted private key or the path to one.
	*	@param string $password The private key passphrase, if it has one.
	*	@return void
	*/

	public function __construct($cert,$passphrase = '')
	{
		$this->private_cert = $cert;
		$this->private_cert_passphrase = $passphrase;
	}

	/**
	*	Generate an RSA signature per OAuth 1.0 Section 9.3.1.
	*
	*	@param string $method The HTTP request method.
	*	@param string $url The HTTP request URL.
	* 	@param array $params An array of params.
	*	@param OAuthKey $token The access/request token to sign with. 
	*	@return string The signiture.
	*/

	public function generate($method, $url, $params, $consumer_secret, $token = null)
	{
		$base_string = $this->signature_base_string($method, $url, $params);

		$keyid = openssl_get_privatekey($this->private_cert, $this->private_cert_passphrase);

		if ($keyid == false)
		{
			throw new OAuthException("RSA private key is invalid. ".openssl_error_string());
		}

		// Section 9.3.1: Sign base_string with consumer's private key.
		if (openssl_sign($base_string, $signature, $keyid))
		{
			openssl_free_key($keyid);
			return base64_encode($signature);
		}
		else throw new OAuthException("Unable to create RSA signature. ".openssl_error_string());
	}
}

/**
*	OAuth Signing Method: Plaintext
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
	*	@param OAuthKey $token The access/request token to sign with. 
	*	@return string The signiture.
	*/

	public function generate($method, $url, $params, $consumer_secret, $token = null)
	{
		$parts = array(
			$consumer_secret,
			($token) ? $token->secret : ''
		);
		$key = OAuthHelper::url_encode(implode('&',$parts));

		return $key;
	}
}

###############################################################################
# 
#	OAUTH SENDERS
#	Handles the transport of OAuth data across HTTP.
#
###############################################################################

/**
*	OAuth Sender Interface
*
*	Provides a simple interface used to transmit OAuth data over HTTP.
*/

interface OAuthSender
{
	/**
	*	Send a new HTTP request.
	*
	*	@param string $url The url to transport to.
	*	@param string $method The method to use ('GET', 'POST', etc.)
	*	@param string $params The parameters to send.
	*	@param string $headers The headers to include when sending.
	*	@return OAuthResponse The sender output.
	*/

	public function request($method, $url, $params = null, $header = null);

	/**
	*	Check if an error occured during transport.
	*
	*	@return string Error description, empty on noerror.
	*/

	public function error();
}

/**
*	OAuth Curl Sender
*
*	A simple curl based sender that impliments the OAuthSender interface.
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
	*	@param string $method The method to use ('GET' or 'POST')
	*	@param string $params The parameters to send.
	*	@param string $headers The headers to include when sending.
	*	@return OAuthResponse The sender output.
	*/

	public function request($method, $url, $params = null, $header = null)
	{
		$options = array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_FAILONERROR => true,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_HEADER => true
		);

		switch($method)
		{
			case "GET":
				$options[CURLOPT_URL] = "$url?$params";
				$options[CURLOPT_HTTPHEADER] = array($header);
				$options[CURLOPT_HTTPGET] = true;
				break;
			case "POST":
				$options[CURLOPT_URL] = $url;
				$options[CURLOPT_HTTPHEADER] = array($header);
				$options[CURLOPT_POST] = true;
				$options[CURLOPT_POSTFIELDS] = $params;
				break;
			default:
				throw new OAuthException("Invalid HTTP method '$method'.");
		}
		curl_setopt_array($this->ch,$options);

		$raw = curl_exec($this->ch);

		// parse output
		$code = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
		$header_size = curl_getinfo($this->ch, CURLINFO_HEADER_SIZE);
		$header = mb_substr($raw,0,$header_size);
		$data = mb_substr($raw,$header_size);
		$type = curl_getinfo($this->ch,CURLINFO_CONTENT_TYPE);

		return new OAuthResponse($raw,$code,$header,$data,$type);
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

###############################################################################
# 
#	OAUTH UTILITIES AND HELPERS
#	Additional utilities, helpers, and storage objects.
#
###############################################################################

/**
*	OAuth access/request token storage object
*
*	Not much to see here.
*/

class OAuthKey
{
	public $key;
	public $secret;

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

/**
*	OAuth Exception Object
*
*	Not much to see here.
*/

class OAuthException extends Exception
{

}

/**
*	OAuth Helpes
*/

class OAuthHelper
{
	/**
	*	Encode values for HTTP url transport per rfc3986.
	*
	*	@param varies $input The value or array to be encoded.
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
	*	Decode rfc3986 encoded HTTP values.
	*
	*	@param string $input The value to be decoded.
	*	@return string The decoded value.
	*/

	static public function url_decode($input)
	{
		return urldecode($input);
	}

	/**
	*	Decodes parameters from an HTTP URL query string
	*
	*	@param string $input The query string to be decoded.
	*	@return aray The decoded parameters as an associative array.
	*/

	static public function param_decode($input)
	{
		$parts = explode('&',$input);

		$params = array();
		foreach($parts as $part)
		{
			$split = explode('=',$part,2);
			$key = OAuthHelper::url_decode($split[0]);
			$value = isset($split[1]) ? OAuthHelper::url_decode($split[1]) : '';

			if (isset($params[$key]))
			{
				// this key has already been added, store additional values
				if ( is_scalar($params[$key]))
				{
					// first duplicated value for this key
					$params[$key] = array($params[$key]);
				}
				$params[$key][] = $value;
			}

			$params[$key] = $value;
		}

		return $params;
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

	/**
	*	Clean up and correctly format a URL for transport.
	*
	*	@param string $url The url to be formatted.
	*	@return string The formatted url.
	*/

	static public function url_format($url)
	{
		$parts = parse_url($url);

		// Section 9.1.2: The url scheme and host must be lowercase and include the port number.
		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : 80);
		$host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		// Section 9.1.2: The default ports for HTTP (80) and HTTPS (443) must NOT be included.
		if (($scheme == 'http' and $port != '80') or ($scheme == 'https' and $port != '443'))
		{
			$host = "$host:$port";
		}

		return "$scheme://$host$path";
	}

}
