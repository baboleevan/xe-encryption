<?php

/**
 * XE 암호화 모듈 (공통 클래스)
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
class Encryption extends ModuleObject
{
	/**
	 * 기본 설정 정의.
	 */
	protected static $default_config = array(
		'aes_bits' => 128,
		'aes_hmac_bits' => 128,
		'aes_store' => 'DB',
		'aes_key' => null,
		'rsa_bits' => 2048,
		'rsa_hmac_bits' => 128,
		'rsa_store' => 'DB',
		'rsa_privkey' => null,
		'rsa_pubkey' => null,
	);
	
	/**
	 * 암호화 키 길이를 간략하게 표현하기 위한 변환표.
	 */
	protected static $shortcuts = array(
		128 => 'A',
		192 => 'B',
		256 => 'C',
		384 => 'D',
		512 => 'E',
		768 => 'F',
		1024 => 'G',
		2048 => 'H',
		3072 => 'I',
		4096 => 'J',
		5120 => 'K',
		6144 => 'L',
		7168 => 'M',
		8192 => 'N',
	);
	
	/**
	 * 모듈 설정을 불러오는 메소드.
	 */
	public function getConfig()
	{
		// DB에서 모듈 설정을 불러온다.
		$config = getModel('module')->getModuleConfig('encryption');
		if (!is_object($config))
		{
			$config = new stdClass();
		}
		
		// 누락된 항목은 기본 설정으로 덮어씌운다.
		foreach (self::$default_config as $key => $val)
		{
			if (!isset($config->{$key}))
			{
				$config->{$key} = $val;
			}
		}
		
		// AES 키가 별도 파일에 저장되어 있는 경우 읽어들인다.
		if ($config->aes_store !== 'DB' && $config->aes_key === null)
		{
			if (@file_exists($config->aes_store))
			{
				$config->aes_key = trim(file_get_contents($config->aes_store));
				if (strlen($config->aes_key) === 0) $config->aes_key = null;
			}
		}
		
		// RSA 키가 별도 파일에 저장되어 있는 경우 읽어들인다.
		if ($config->rsa_store !== 'DB' && $config->rsa_privkey === null && $config->rsa_pubkey === null)
		{
			if (@file_exists($config->rsa_store))
			{
				$rsa_key = trim(file_get_contents($config->rsa_store));
				if (strlen($rsa_key) === 0) $rsa_key = null;
				if (preg_match('/-----BEGIN (ENCRYPTED )?PRIVATE KEY-----(.+)-----END (ENCRYPTED )?PRIVATE KEY-----/sU', $rsa_key, $matches))
				{
					$config->rsa_privkey = $matches[0] . "\n";
				}
				if (preg_match('/-----BEGIN PUBLIC KEY-----(.+)-----END PUBLIC KEY-----/sU', $rsa_key, $matches))
				{
					$config->rsa_pubkey = $matches[0] . "\n";
				}
			}
		}
		
		return $config;
	}
	
	/**
	 * 주어진 길이의 랜덤 문자열을 생성하는 메소드.
	 */
	public function getRandomString($length)
	{
		static $fp = null;
		
		if ($fp === null)
		{
			$fp = strncasecmp(PHP_OS, 'WIN', 3) ? @fopen('/dev/urandom', 'rb') : false;
		}
		
		if ($fp)
		{
			return fread($fp, $length);
		}
		elseif (version_compare(PHP_VERSION, '5.4', '>=') || strncasecmp(PHP_OS, 'WIN', 3))
		{
			return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
		}
		else
		{
			return mcrypt_create_iv($length);
		}
	}
	
	public function moduleInstall()
	{
		return new Object();
	}
	
	public function checkUpdate()
	{
		return false;
	}
	
	public function moduleUpdate()
	{
		return new Object(0, 'success_updated');
	}
	
	public function recompileCache()
	{
		// no-op
	}
}
