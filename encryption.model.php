<?php

/**
 * XE 암호화 모듈 (모델)
 * 
 * Copyright (c) 2015, Kijin Sung <kijin@kijinsung.com>
 * 
 * 이 라이브러리는 자유 소프트웨어입니다. 소프트웨어의 피양도자는 자유
 * 소프트웨어 재단이 공표한 GNU 약소 일반 공중 사용 허가서 (GNU LGPL) 2.1판
 * 또는 그 이후 판을 임의로 선택해서, 그 규정에 따라 라이브러리를 개작하거나
 * 재배포할 수 있습니다.
 *
 * 이 라이브러리는 유용하게 사용될 수 있으리라는 희망에서 배포되고 있지만,
 * 특정한 목적에 맞는 적합성 여부나 판매용으로 사용할 수 있으리라는 묵시적인
 * 보증을 포함한 어떠한 형태의 보증도 제공하지 않습니다. 보다 자세한 사항에
 * 대해서는 GNU 약소 일반 공중 사용 허가서를 참고하시기 바랍니다.
 *
 * GNU 약소 일반 공중 사용 허가서는 이 라이브러리와 함께 제공됩니다. 만약
 * 이 문서가 누락되어 있다면 자유 소프트웨어 재단으로 문의하시기 바랍니다.
 */
class EncryptionModel extends Encryption
{
	/**
	 * 모듈 설정을 여러 번 불러오지 않도록 캐싱해 두는 변수.
	 */
	protected $config = null;
	protected $extension = null;
	
	/**
	 * 생성자.
	 */
	public function __construct()
	{
		if (version_compare(PHP_VERSION, '5.4', '>=') && function_exists('openssl_encrypt'))
		{
			$this->extension = 'openssl';
		}
		else
		{
			$this->extension = 'mcrypt';
		}
	}
	
	/**
	 * 대칭키(AES) 알고리듬으로 문자열을 암호화한다.
	 * 암호화에 성공한 경우 그 결과를 반환하며, 비밀키가 생성되지 않은 경우 false를 반환한다.
	 */
	public function aesEncrypt($plaintext)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->aes_key === null) return false;
		
		// 비밀키로부터 암호화 키를 생성한다.
		$key_size = intval($this->config->aes_bits / 8);
		$key = substr(hash('sha256', $this->config->aes_key . ':AES-KEY', true), 0, $key_size);
		
		// 초기화 벡터를 생성한다.
		$iv = $this->getRandomString(16);
		
		// 서버 환경에 따라 openssl 또는 mcrypt 모듈을 사용하여 암호화한다.
		if ($this->extension === 'openssl')
		{
			$openssl_method = 'aes-' . $this->config->aes_bits . '-cbc';
			$ciphertext = openssl_encrypt($plaintext, $openssl_method, $key, OPENSSL_RAW_DATA, $iv);
        }
		else
		{
			$plaintext = $this->applyPKCS7Padding($plaintext, 16);
			$ciphertext = mcrypt_encrypt('rijndael-128', $key, $plaintext, 'cbc', $iv);
		}
		
		// HMAC을 생성한다.
		$hmac_size = intval($this->config->aes_hmac_bits / 8);
		$hmac_key = hash('sha256', $this->config->aes_key . ':HMAC-KEY', true);
		$hmac = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		
		// 결과를 포맷하여 반환한다.
		$meta = $this->createMetadata('A', 'E', $this->config->aes_bits, $this->config->aes_hmac_bits);
		return $meta . base64_encode($iv . $hmac . $ciphertext);
	}
	
	/**
	 * 대칭키(AES) 알고리듬으로 암호화된 문자열을 복호화한다.
	 * 복호화에 성공한 경우 평문을 반환하며, 비밀키가 생성되지 않았거나
	 * 정상적인 암호문이 아닌 경우에는 false를 반환한다.
	 */
	public function aesDecrypt($ciphertext)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->aes_key === null) return false;
		
		// 암호화에 사용된 키의 종류 및 HMAC 길이를 파악한다.
		$meta = $this->decodeMetadata(substr($ciphertext, 0, 4));
		if ($meta->encryption_type !== 'A') return false;
		if (!$meta->bits || !$meta->hmac_bits) return false;
		
		// 버전에 따라 다른 메소드를 호출한다.
		switch ($meta->key_type)
		{
			case 'E': return $this->aesDecrypt_v2($ciphertext, $meta);
			case 'K': return $this->aesDecrypt_v1($ciphertext, $meta);
			default: return false;
		}
	}
	
	/**
	 * 대칭키(AES) 복호화 서브루틴: 개선된 버전.
	 */
	public function aesDecrypt_v2($ciphertext, $meta)
	{
		// 사용할 키 길이 및 초기화 벡터 크기를 구한다.
		$iv_size = mcrypt_get_iv_size('rijndael-128', 'cbc');
		$hmac_size = intval($meta->hmac_bits / 8);
		
		// 암호문에서 초기화 벡터와 HMAC을 분리한다.
		if (strlen($ciphertext) % 4 !== 0) return false;
		$ciphertext = @base64_decode(substr($ciphertext, 4));
		if ($ciphertext === false) return false;
		if (strlen($ciphertext) <= $iv_size + $hmac_size) return false;
		$iv = substr($ciphertext, 0, $iv_size);
		$hmac = substr($ciphertext, $iv_size, $hmac_size);
		$ciphertext = substr($ciphertext, $iv_size + $hmac_size);
		
		// 비밀키로부터 암호화 키를 생성한다.
		$key_size = intval($meta->bits / 8);
		$key = substr(hash('sha256', $this->config->aes_key . ':AES-KEY', true), 0, $key_size);
		
		// HMAC이 일치하는지 체크한다.
		$hmac_key = hash('sha256', $this->config->aes_key . ':HMAC-KEY', true);
		$hmac_check = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		if ($hmac !== $hmac_check) return false;
		
		// 서버 환경에 따라 openssl 또는 mcrypt 모듈을 사용하여 복호화한다.
		if ($this->extension === 'openssl')
		{
			$openssl_method = 'aes-' . $this->config->aes_bits . '-cbc';
			$plaintext = openssl_decrypt($ciphertext, $openssl_method, $key, OPENSSL_RAW_DATA, $iv);
        }
		else
		{
			$plaintext = @mcrypt_decrypt('rijndael-128', $key, $ciphertext, 'cbc', $iv);
			if ($plaintext === false) return false;
			$plaintext = $this->stripPKCS7Padding($plaintext, 16);
			if ($plaintext === false) return false;
		}
		
		// 평문을 반환한다.
		return $plaintext;
	}
	
	/**
	 * 대칭키(AES) 복호화 서브루틴: 기존 버전.
	 */
	public function aesDecrypt_v1($ciphertext, $meta)
	{
		// 사용할 키 길이 및 초기화 벡터 크기를 구한다.
		$cipher = 'rijndael-' . $meta->bits;
		$iv_size = mcrypt_get_iv_size($cipher, 'cbc');
		$hmac_size = intval($meta->hmac_bits / 8);
		
		// 암호문에서 초기화 벡터와 HMAC을 분리한다.
		if (strlen($ciphertext) % 4 !== 0) return false;
		$ciphertext = @base64_decode(substr($ciphertext, 4));
		if ($ciphertext === false) return false;
		if (strlen($ciphertext) <= $iv_size + $hmac_size) return false;
		$iv = substr($ciphertext, 0, $iv_size);
		$hmac = substr($ciphertext, $iv_size, $hmac_size);
		$ciphertext = substr($ciphertext, $iv_size + $hmac_size);
		
		// 비밀키로부터 암호화 키를 생성한다.
		$key_size = mcrypt_get_key_size($cipher, 'cbc');
		$key = substr(hash('sha256', $this->config->aes_key, true), 0, $key_size);
		
		// HMAC이 일치하는지 체크한다.
		$hmac_check = substr(hash_hmac('sha256', $ciphertext, $key . $iv, true), 0, $hmac_size);
		if ($hmac !== $hmac_check) return false;
		
		// 복호화를 시도한다.
		$plaintext = @mcrypt_decrypt($cipher, $key, $ciphertext, 'cbc', $iv);
		if ($plaintext === false) return false;
		
		// 압축을 해제하여 평문을 구한다.
		$plaintext = @gzuncompress($plaintext);
		if ($plaintext === false) return false;
		return $plaintext;
	}
	
	/**
	 * 비대칭키(RSA) 알고리듬의 공개키를 사용하여 문자열을 암호화한다.
	 * 이 방법으로 암호화한 문자열은 개인키를 사용하여 복호화할 수 있다.
	 * 암호화에 성공한 경우 그 결과를 반환하며, 비밀키가 생성되지 않은 경우 false를 반환한다.
	 */
	public function rsaEncryptWithPublicKey($plaintext)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->rsa_pubkey === null) return false;
		
		// 공개키를 가져온다.
		$pubkey = @openssl_pkey_get_public($this->config->rsa_pubkey);
		if ($pubkey === false) return false;
		
		// 평문을 암호화한다.
		$ciphertext = false;
		$status = @openssl_public_encrypt($plaintext, $ciphertext, $pubkey);
		@openssl_pkey_free($pubkey);
		if (!$status || $ciphertext === false) return false;
		
		// HMAC을 생성한다.
		$hmac_key = hash('sha256', trim($this->config->rsa_pubkey));
		$hmac_size = intval($this->config->rsa_hmac_bits / 8);
		$hmac = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		
		// 결과를 포맷하여 반환한다.
		$meta = $this->createMetadata('R', 'B', $this->config->rsa_bits, $this->config->rsa_hmac_bits);
		return $meta . base64_encode($hmac . $ciphertext);
	}
	
	/**
	 * 비대칭키(RSA) 알고리듬의 개인키로 암호화된 문자열을 공개키로 복호화한다.
	 * 복호화에 성공한 경우 평문을 반환하며, 비밀키가 생성되지 않았거나
	 * 정상적인 암호문이 아닌 경우에는 false를 반환한다.
	 */
	public function rsaDecryptWithPublicKey($ciphertext)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->rsa_pubkey === null) return false;
		
		// 암호화에 사용된 키의 종류 및 HMAC 길이를 파악한다.
		$meta = $this->decodeMetadata(substr($ciphertext, 0, 4));
		if ($meta->encryption_type !== 'R') return false;
		if ($meta->key_type !== 'A' && $meta->key_type !== 'P') return false;
		if (!$meta->bits || !$meta->hmac_bits) return false;
		$hmac_size = intval($meta->hmac_bits / 8);
		
		// 암호문에서 초기화 벡터와 HMAC을 분리한다.
		$ciphertext = @base64_decode(substr($ciphertext, 4));
		if ($ciphertext === false) return false;
		if (strlen($ciphertext) <= $hmac_size) return false;
		$hmac = substr($ciphertext, 0, $hmac_size);
		$ciphertext = substr($ciphertext, $hmac_size);
		
		// HMAC이 일치하는지 체크한다.
		$hmac_key = hash('sha256', trim($this->config->rsa_pubkey));
		$hmac_check = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		if ($hmac !== $hmac_check) return false;
		
		// 공개키를 가져온다.
		$pubkey = @openssl_pkey_get_public($this->config->rsa_pubkey);
		if ($pubkey === false) return false;
		
		// 복호화를 시도한다.
		$plaintext = false;
		$status = @openssl_public_decrypt($ciphertext, $plaintext, $pubkey);
		@openssl_pkey_free($pubkey);
		if (!$status || $plaintext === false) return false;
		
		// 압축된 평문인 경우 압축을 해제한다.
		if ($meta->key_type === 'P')
		{
			$plaintext = @gzuncompress($plaintext);
			if ($plaintext === false) return false;
		}
		
		// 평문을 반환한다.
		return $plaintext;
	}
	
	/**
	 * 비대칭키(RSA) 알고리듬의 개인키를 사용하여 문자열을 암호화한다.
	 * 이 방법으로 암호화한 문자열은 공개키를 사용하여 복호화할 수 있다.
	 * 암호화에 성공한 경우 그 결과를 반환하며, 비밀키가 생성되지 않은 경우 false를 반환한다.
	 */
	public function rsaEncryptWithPrivateKey($plaintext, $passphrase = null)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->rsa_privkey === null || $this->config->rsa_pubkey === null) return false;
		
		// 개인키를 가져온다.
		$privkey = @openssl_pkey_get_private($this->config->rsa_privkey, strval($passphrase));
		if ($privkey === false) return false;
		
		// 평문을 암호화한다.
		$ciphertext = false;
		$status = @openssl_private_encrypt($plaintext, $ciphertext, $privkey);
		@openssl_pkey_free($privkey);
		if (!$status || $ciphertext === false) return false;
		
		// HMAC을 생성한다.
		$hmac_key = hash('sha256', trim($this->config->rsa_pubkey));
		$hmac_size = intval($this->config->rsa_hmac_bits / 8);
		$hmac = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		
		// 결과를 포맷하여 반환한다.
		$meta = $this->createMetadata('R', 'A', $this->config->rsa_bits, $this->config->rsa_hmac_bits);
		return $meta . base64_encode($hmac . $ciphertext);
	}
	
	/**
	 * 비대칭키(RSA) 알고리듬의 공개키로 암호화된 문자열을 개인키로 복호화한다.
	 * 복호화에 성공한 경우 평문을 반환하며, 비밀키가 생성되지 않았거나
	 * 정상적인 암호문이 아닌 경우에는 false를 반환한다.
	 */
	public function rsaDecryptWithPrivateKey($ciphertext, $passphrase = null)
	{
		// 모듈 설정을 확인한다.
		if ($this->config === null) $this->config = $this->getConfig();
		if ($this->config->rsa_privkey === null || $this->config->rsa_pubkey === null) return false;
		
		// 암호화에 사용된 키의 종류 및 HMAC 길이를 파악한다.
		$meta = $this->decodeMetadata(substr($ciphertext, 0, 4));
		if ($meta->encryption_type !== 'R') return false;
		if ($meta->key_type !== 'B' && $meta->key_type !== 'U') return false;
		if (!$meta->bits || !$meta->hmac_bits) return false;
		$hmac_size = intval($meta->hmac_bits / 8);
		
		// 암호문에서 초기화 벡터와 HMAC을 분리한다.
		$ciphertext = @base64_decode(substr($ciphertext, 4));
		if ($ciphertext === false) return false;
		if (strlen($ciphertext) <= $hmac_size) return false;
		$hmac = substr($ciphertext, 0, $hmac_size);
		$ciphertext = substr($ciphertext, $hmac_size);
		
		// HMAC이 일치하는지 체크한다.
		$hmac_key = hash('sha256', trim($this->config->rsa_pubkey));
		$hmac_check = substr(hash_hmac('sha256', $ciphertext, $hmac_key, true), 0, $hmac_size);
		if ($hmac !== $hmac_check) return false;
		
		// 개인키를 가져온다.
		$privkey = @openssl_pkey_get_private($this->config->rsa_privkey, strval($passphrase));
		if ($privkey === false) return false;
		
		// 복호화를 시도한다.
		$plaintext = false;
		$status = @openssl_private_decrypt($ciphertext, $plaintext, $privkey);
		@openssl_pkey_free($privkey);
		if (!$status || $plaintext === false) return false;
		
		// 압축된 평문인 경우 압축을 해제한다.
		if ($meta->key_type === 'U')
		{
			$plaintext = @gzuncompress($plaintext);
			if ($plaintext === false) return false;
		}
		
		// 평문을 반환한다.
		return $plaintext;
	}
	
	/**
	 * PKCS7 패딩을 적용한다.
	 */
	protected function applyPKCS7Padding($str, $block_size)
	{
		$padding_size = $block_size - (strlen($str) % $block_size);
		if ($padding_size === 0) $padding_size = $block_size;
		return $str . str_repeat(chr($padding_size), $padding_size);
	}
	
	/**
	 * PKCS7 패딩을 제거한다.
	 */
	protected function stripPKCS7Padding($str, $block_size)
	{
		if (strlen($str) % $block_size !== 0) return false;
		$padding_size = ord(substr($str, -1));
		if ($padding_size < 1 || $padding_size > $block_size) return false;
		if (substr($str, (-1 * $padding_size)) !== str_repeat(chr($padding_size), $padding_size)) return false;
		return substr($str, 0, strlen($str) - $padding_size);
	}
	
	/**
	 * 알고리듬 종류, 비트 수, HMAC 길이 등을 4바이트로 정리하여 인코딩한다.
	 */
	protected function createMetadata($cipher, $key_type, $bits, $hmac_bits)
	{
		return $cipher . $key_type . self::$shortcuts[$bits] . self::$shortcuts[$hmac_bits];
	}
	
	/**
	 * 위의 메소드로 인코딩된 정보를 추출한다.
	 */
	protected function decodeMetadata($metadata)
	{
		return (object)array(
			'encryption_type' => $metadata[0],
			'key_type' => $metadata[1],
			'bits' => array_search($metadata[2], self::$shortcuts),
			'hmac_bits' => array_search($metadata[3], self::$shortcuts),
		);
	}
}
