<?php

/**
 * XE 암호화 모듈 (관리자 모델)
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
class EncryptionAdminModel extends Encryption
{
	/**
	 * 새 AES 비밀키를 생성하는 메소드. AJAX로 호출된다.
	 */
	public function getEncryptionAdminNewAESKey()
	{
		// 랜덤 문자열을 생성한 후, 여러 번 mixing한다.
		$entropy = $this->getRandomString(48);
		for ($i = 0; $i < 16; $i++)
		{
			$entropy = hash('sha512', $entropy . $i, true);
		}
		
		// Base64로 인코딩하고 64자를 잘라 반환한다.
		$entropy = substr(base64_encode($entropy), 0, 64);
		$this->add('newkey', $entropy);
	}
	
	/**
	 * 새 RSA 개인키/공개키 조합을 생성하는 메소드. AJAX로 호출된다.
	 */
	public function getEncryptionAdminNewRSAKey()
	{
		// 생성할 키의 크기를 구하고, 1024의 배수로 변환한다.
		$args = Context::getRequestVars();
		$bits = intval(max(1024, round($args->key_size / 1024) * 1024));
		
		// 새 키를 생성한다.
		$res = openssl_pkey_new(array(
			'digest_alg' => 'sha256',
			'private_key_bits' => $bits,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		));
		
		// 개인키를 PEM 포맷으로 변환한다.
		openssl_pkey_export($res, $private_key);
		
		// 공개키를 PEM 포맷으로 변환한다.
		$public_key = openssl_pkey_get_details($res);
		$public_key = $public_key['key'];
		
		// 생성한 키 조합을 반환한다.
		$this->add('privkey', $private_key);
		$this->add('pubkey', $public_key);
	}
}
