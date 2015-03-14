<?php

/**
 * XE 암호화 모듈 (관리자 컨트롤러)
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
class EncryptionAdminController extends Encryption
{
	/**
	 * 모듈 설정을 저장하는 메소드.
	 */
	public function procEncryptionAdminInsertConfig()
	{
		// 기존 설정을 가져온다.
		$current_config = $this->getConfig();
		
		// 새로 저장하려는 설정을 가져온다.
		$request_args = Context::getRequestVars();
		
		// 주어진 설정을 정리한다.
		$args = new stdClass();
		$args->aes_bits = $request_args->aes_bits;
		$args->aes_hmac_bits = $request_args->aes_hmac_bits;
		$args->aes_store = $request_args->aes_store === 'file' ? $request_args->aes_store_filename : 'DB';
		$args->aes_key = strlen(trim($request_args->aes_key)) ? trim($request_args->aes_key) : null;
		$args->rsa_bits = $request_args->rsa_bits;
		$args->rsa_hmac_bits = $request_args->rsa_hmac_bits;
		$args->rsa_store = $request_args->rsa_store === 'file' ? $request_args->rsa_store_filename : 'DB';
		$args->rsa_privkey = strlen(trim($request_args->rsa_privkey)) ? trim($request_args->rsa_privkey) : null;
		$args->rsa_pubkey = strlen(trim($request_args->rsa_pubkey)) ? trim($request_args->rsa_pubkey) : null;
		
		// 키가 없는 경우 null로 정리하고, 파일에 저장하지 않도록 조치한다.
		if ($args->rsa_privkey === null) $args->rsa_pubkey = null;
		if ($args->rsa_pubkey === null) $args->rsa_privkey = null;
		if ($args->aes_key === null) $args->aes_store = 'DB';
		if ($args->rsa_privkey === null) $args->rsa_store = 'DB';
		
		// AES 키를 파일에 저장하는 경우 처리.
		if ($args->aes_store !== 'DB' && $args->aes_key !== null)
		{
			// 디렉토리가 존재하지 않는 경우 생성을 시도한다.
			$dir = dirname($args->aes_store);
			if (!file_exists($dir))
			{
				$success = @mkdir($dir, 0755, true);
				if (!$success)
				{
					return $this->stop('msg_encryption_symmetric_key_save_failure');
				}
			}
			
			// 파일 저장을 시도한다.
			$success = @file_put_contents($args->aes_store, $args->aes_key);
			if (!$success)
			{
				return $this->stop('msg_encryption_symmetric_key_save_failure');
			}
			
			// DB에는 키를 저장하지 않도록 한다.
			$args->aes_key = null;
		}
		
		// 파일에 저장했던 AES 키를 DB로 옮기는 경우, 보안을 위해 기존 파일을 삭제한다.
		if ($args->aes_store === 'DB' && $current_config->aes_store !== DB)
		{
			@unlink($current_config->aes_store);
		}
		
		// AES 키를 파일에 저장하는 경우 처리.
		if ($args->rsa_store !== 'DB' && $args->rsa_privkey !== null)
		{
			// 디렉토리가 존재하지 않는 경우 생성을 시도한다.
			$dir = dirname($args->rsa_store);
			if (!file_exists($dir))
			{
				$success = @mkdir($dir, 0755, true);
				if (!$success)
				{
					return $this->stop('msg_encryption_asymmetric_key_save_failure');
				}
			}
			
			// 파일 저장을 시도한다.
			$keydata = $args->rsa_privkey . "\n" . $args->rsa_pubkey . "\n";
			$success = @file_put_contents($args->rsa_store, $keydata);
			if (!$success)
			{
				return $this->stop('msg_encryption_asymmetric_key_save_failure');
			}
			
			// DB에는 키를 저장하지 않도록 한다.
			$args->rsa_privkey = null;
			$args->rsa_pubkey = null;
		}
		
		// 파일에 저장했던 RSA 키를 DB로 옮기는 경우, 보안을 위해 기존 파일을 삭제한다.
		if ($args->rsa_store === 'DB' && $current_config->rsa_store !== DB)
		{
			@unlink($current_config->rsa_store);
		}
		
		// 새 모듈 설정을 저장한다.
		$oModuleController = getController('module');
		$output = $oModuleController->insertModuleConfig('encryption', $args);
		if ($output->toBool())
		{
			$this->setMessage('success_registed');
		}
		else
		{
			return $output;
		}
		
		if (Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'module', 'encryption', 'act', 'dispEncryptionAdminConfig'));
		}
	}
}
