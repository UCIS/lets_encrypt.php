#!/usr/bin/env php
<?php
/* Copyright 2016-2019 Ivo Smits <Ivo@UCIS.nl>. All rights reserved. This software may be used and distributed under the Simplified BSD License. */

if (PHP_SAPI != 'cli') die("This script should be called from the command line!\n");

error_reporting(E_ALL);
set_error_handler(function($errno, $errstr, $errfile, $errline) {
	if (!(error_reporting() & $errno)) return;
	throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
});

if (!function_exists('hex2bin')) {
	function hex2bin($hex) { return pack('H*', $hex); }
}

$options = getopt('r:a:e:c:d:ps');

if (!$options || !isset($options['r'], $options['d'])) die("Usage: ".(@$_SERVER['argv'][0])." -r [www-root] -d [domain] (-d [domain]...) (-c [certificate-file]) (-a [account-key-file]) (-e [contact-email-address]) (-p) (-t) (-s)\n");

$www_root = $options['r'];
$account_key_file = isset($options['a']) ? $options['a'] : NULL;
$account_email = isset($options['e']) ? $options['e'] : NULL;
$server_cert_file = isset($options['c']) ? $options['c'] : NULL;
$server_cert_print = !isset($server_cert_file) || isset($options['p']);
$domains = (array)$options['d'];
$use_staging_server = isset($options['s']);

$directory = $use_staging_server ? 'https://acme-staging-v02.api.letsencrypt.org/directory' : 'https://acme-v02.api.letsencrypt.org/directory';
$directory = file_get_contents($directory, false, stream_context_create(array('http' => array('timeout' => 10))));
$directory = json_decode($directory, TRUE);

if ($account_key_file != '-' && file_exists($account_key_file)) {
	$account_key = openssl_pkey_get_private('file://'.$account_key_file);
} else {
	$account_key = openssl_pkey_new(array('private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
	if (!empty($account_key_file)) openssl_pkey_export_to_file($account_key, $account_key_file);
}

if (!empty($server_cert_file) && file_exists($server_cert_file)) {
	$server_key = openssl_pkey_get_private('file://'.$server_cert_file);
} else {
	$server_key = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
}

$acme_nonce = NULL;
$account_key_id = NULL;

$registration = array('termsOfServiceAgreed' => TRUE);
if (!empty($account_email)) $registration['contact'] = array('mailto:'.$account_email);
signed_request($directory['newAccount'], $registration);
$certdata = get_certificate($server_key, $domains, domain_authorization_challenge_callback($www_root));
if (substr($certdata, 0, 26) !== '-----BEGIN CERTIFICATE----') throw new Exception('Invalid certificate data received'); //Sanity check so openssl won't try to open some local file

$cert = openssl_x509_read($certdata);
if (!openssl_x509_check_private_key($cert, $server_key)) throw new Exception('The obtained certificate does not match the private key');

$bundle = build_pem_bundle($server_key, $certdata);

if (!empty($server_cert_file)) file_put_contents($server_cert_file, $bundle);

if ($server_cert_print) echo $bundle;

function build_pem_bundle($key, $cert) {
	$pem = '';
	openssl_pkey_export($key, $pem);
	$pem .= "\r\n";
	$pem .= $cert;
	$pem .= "\r\n";
	return $pem;
}

function domain_authorization_challenge_callback($path) {
	if (!is_dir($path)) mkdir($path, 0777, true);
	return function($sub, $value, $token) use ($path) {
		if ($value === NULL) unlink($path.$sub);
		else file_put_contents($path.$sub, $value);
	};
}

function get_certificate($server_key, $domains, $challenge_callback) {
	global $directory, $account_key;
	$account_key_params = openssl_pkey_get_details($account_key);
	$account_thumb_print = json_encode(array(
		'e'=> urlbase64($account_key_params['rsa']['e']),
		'kty' => 'RSA',
		'n' => urlbase64($account_key_params['rsa']['n']),
	));
	$account_thumb_print = hash('sha256', $account_thumb_print, true);
	$account_thumb_print = urlbase64($account_thumb_print);
	if (!is_array($domains)) $domains = array($domains);
	$identifiers = array();
	foreach ($domains as $domain) $identifiers[] = array('type' => 'dns', 'value' => (string)$domain);
	$response = signed_request($directory['newOrder'], array('identifiers' => $identifiers));
	$order = json_decode($response, TRUE);
	foreach ($order['authorizations'] as $authorization) {
		$response = signed_request($authorization);
		$response = json_decode($response, TRUE);
		if ($response['status'] !== 'pending') continue;
		$domain = $response['identifier']['value'];
		foreach ($response['challenges'] as $challenge) {
			if ($challenge['status'] !== 'pending') continue;
			if ($challenge['type'] === 'http-01') {
				if (preg_match('[^a-zA-Z0-9_-]', $challenge['token']) !== 0) throw new Exception('Challenge token contains illegal characters');
				$keyauth = $challenge['token'].'.'.$account_thumb_print;
				$challenge_callback('/.well-known/acme-challenge/'.$challenge['token'], $keyauth, $challenge['token']);
				try {
					$response = signed_request($challenge['url'], new stdClass());
					$response = json_decode($response, true);
					while ($response['status'] === 'pending' || $response['status'] === 'processing') {
						usleep(500000); //0.5sec
						$response = signed_request($authorization);
						$response = json_decode($response, TRUE);
					}
					$challenge_callback('/.well-known/acme-challenge/'.$challenge['token'], NULL, $challenge['token']);
				} catch (Exception $ex) {
					$challenge_callback('/.well-known/acme-challenge/'.$challenge['token'], NULL, $challenge['token']);
					throw $ex;
				}
				if ($response['status'] !== 'valid') throw new Exception('Challenge rejected for domain '.$domain.' ('.$response['status'].')');
			}
		}
	}
	$csr = generateCertificateSigningRequest($server_key, $domains);
	$response = signed_request($order['finalize'], array('csr' => urlbase64($csr)));
	$order = json_decode($response, TRUE);
	$response = signed_request($order['certificate']);
	return $response;
}

function signed_request($url, $payload = NULL, $accept_errors = array()) {
	global $directory, $acme_nonce, $account_key, $account_key_id;
	if (substr($url, 0, 8) !== 'https://') throw new Exception('Invalid endpoint');
	if ($acme_nonce === NULL) {
		if (substr($directory['newNonce'], 0, 8) !== 'https://') throw new Exception('Invalid newNonce endpoint');
		file_get_contents($directory['newNonce'], false, stream_context_create(array('http' => array('timeout' => 10, 'method' => 'HEAD'))));
		$acme_nonce = get_http_response_header($http_response_header, 'Replay-Nonce');
	}
	$protected = array('alg' => 'RS256', 'nonce' => $acme_nonce, 'url' => $url);
	if ($account_key_id === NULL) {
		$account_key_params = openssl_pkey_get_details($account_key);
		$protected['jwk'] = array('e'=> urlbase64($account_key_params['rsa']['e']), 'kty' => 'RSA', 'n' => urlbase64($account_key_params['rsa']['n']));
	} else {
		$protected['kid'] = $account_key_id;
	}
	$protected = urlbase64(json_encode($protected));
	$acme_nonce = NULL;
	$payload = $payload === NULL ? '' : urlbase64(json_encode($payload));
	$signed = NULL;
	openssl_sign($protected.'.'.$payload, $signed, $account_key, 'sha256WithRSAEncryption');
	$signed = urlbase64($signed);
	$data = json_encode(array('protected'=> $protected, 'payload'=> $payload, 'signature'=> $signed));
	$http_options = array('http' => array(
		'timeout' => 10,
		'method' => 'POST',
		'header' => array('Content-Type: application/jose+json'),
		'content' => $data,
		'ignore_errors' => TRUE,
	));
	$ret = file_get_contents($url, false, stream_context_create($http_options));
	$status = get_http_response_header($http_response_header, NULL);
	if (($status < 200 || $status > 299) && !in_array($status, $accept_errors)) throw new Exception('ACME server error: '.$ret);
	$acme_nonce = get_http_response_header($http_response_header, 'Replay-Nonce');
	if ($url === $directory['newAccount']) $account_key_id = get_http_response_header($http_response_header, 'Location'); //Hack. Why couldn't they just put everything in the JSON body?
	return $ret;
}

function get_http_response_header($headers, $name) {
	$value = array_shift($headers); //HTTP/version status description
	$value = explode(' ', $value, 3);
	if ($name === NULL) return $value[1];
	$value = NULL;
	foreach ($headers as $header) {
		if ($header[0] == ' ' || $header[0] == "\t") {
			$value .= $header;
		} else if ($value !== NULL) {
			break;
		} elseif (substr_compare($header, $name.':', 0, strlen($name) + 1, true) == 0) {
			$value = substr($header, strlen($name) + 1);
		}
	}
	if ($value !== NULL) return trim($value);
	return NULL;
}

function urlbase64($value) {
	return str_replace(array('+', '/'), array('-', '_'), rtrim(base64_encode($value), '='));
}

function encodeDerTag($tclass, $tconstructed, $tnumber, $value = '') {
	$ret = '';
	if ($tnumber <= 30) {
		$ret .= chr((($tclass & 3) << 6) | ($tconstructed ? 0x20 : 0x00) | ($tnumber & 0x1F));
	} else {
		$ret .= chr((($tclass & 3) << 6) | ($tconstructed ? 0x20 : 0x00) | 0x31);
		if ($tnumber > 0xFE00000) $ret .= chr(0x80 | (($tnumber >> 28) & 0x7F));
		if ($tnumber > 0x1FC000) $ret .= chr(0x80 | (($tnumber >> 21) & 0x7F));
		if ($tnumber > 0x3F80) $ret .= chr(0x80 | (($tnumber >> 14) & 0x7F));
		if ($tnumber > 0x7F) $ret .= chr(0x80 | (($tnumber >> 7) & 0x7F));
		$ret .= chr($tnumber & 0x7F);
	}
	$value = (string)$value;
	$length = strlen($value);
	if ($length < 0x80) {
		$ret .= chr($length);
	} else if ($length < 0x100) {
		$ret .= chr(0x81);
		$ret .= chr($length);
	} else if (strlen($value) < 0x10000) {
		$ret .= chr(0x82);
		$ret .= chr(($length >> 8) & 0xFF);
		$ret .= chr($length & 0xFF);
	} else if ($length < 0x1000000) {
		$ret .= chr(0x83);
		$ret .= chr(($length >> 16) & 0xFF);
		$ret .= chr(($length >> 8) & 0xFF);
		$ret .= chr($length & 0xFF);
	} else {
		$ret .= chr(0x84);
		$ret .= chr(($length >> 24) & 0xFF);
		$ret .= chr(($length >> 16) & 0xFF);
		$ret .= chr(($length >> 8) & 0xFF);
		$ret .= chr($length & 0xFF);
	}
	return $ret.$value;
}
function generateCertificateSigningRequest($pkey, $domains) {
	$key_params = openssl_pkey_get_details($pkey);
	$altnames = '';
	foreach ($domains as $domain) $altnames .= encodeDerTag(2, false, 0x02, $domain);
	$domain = reset($domains);
	$csr = 
		encodeDerTag(0, true, 0x10, //SEQUENCE
			encodeDerTag(0, false, 0x02, chr(0)). //INTEGER version: 0
			encodeDerTag(0, true, 0x10, //SEQUENCE
				encodeDerTag(0, true, 0x11, //SET
					encodeDerTag(0, true, 0x10, //SEQUENCE
						encodeDerTag(0, false, 0x06, hex2bin('550403')). //OBJECT: commonName
						encodeDerTag(0, false, 0x0C, $domain) //UTF8STRING
					)
				)
			).
			encodeDerTag(0, true, 0x10, //SEQUENCE
				encodeDerTag(0, true, 0x10, //SEQUENCE
					encodeDerTag(0, false, 0x06, hex2bin('2A864886F70D010101')). //OBJECT: rsaEncryption
					encodeDerTag(0, false, 0x05) //NULL
				).
				encodeDerTag(0, false, 0x03, //BIT STRING
					chr(0). //Number of unused bits in final octet
					encodeDerTag(0, true, 0x10, //SEQUENCE
						encodeDerTag(0, false, 0x02, chr(0).$key_params['rsa']['n']). //INTEGER - Don't know why we need the extra zero, but it seems necessary for the CSR to be accepted.
						encodeDerTag(0, false, 0x02, $key_params['rsa']['e']) //INTEGER
					)
				)
			).
			encodeDerTag(2, true, 0x00, //cont[0]
				encodeDerTag(0, true, 0x10, //SEQUENCE
					encodeDerTag(0, false, 0x06, hex2bin('2A864886F70D01090E')). //OBJECT: Extension Request
					encodeDerTag(0, true, 0x11, //SET
						encodeDerTag(0, true, 0x10, //SEQUENCE
							encodeDerTag(0, true, 0x10, //SEQUENCE
								encodeDerTag(0, false, 0x06, hex2bin('551D11')). //OBJECT: X509v3 Subject Alternative Name
								encodeDerTag(0, false, 0x04, //OCTET STRING
									encodeDerTag(0, true, 0x10, $altnames) //SEQUENCE
								)
							)
						)
					)
				)
			)
		);
	$signature = NULL;
	openssl_sign($csr, $signature, $pkey, 'sha256WithRSAEncryption');
	$csr = encodeDerTag(0, true, 0x10, //SEQUENCE
		$csr.
		encodeDerTag(0, true, 0x10, //SEQUENCE
			encodeDerTag(0, false, 0x06, hex2bin('2A864886F70D01010B')). //OBJECT: sha256WithRSAEncryption
			encodeDerTag(0, false, 0x05) //NULL
		).
		encodeDerTag(0, false, 0x03, //BIT STRING
			chr(0). //Number of unused bits in final octet
			$signature
		)
	);
	return $csr;
}
