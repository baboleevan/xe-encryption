<?php

/**
 * XE 암호화 모듈 (관리자 뷰)
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
class EncryptionAdminView extends Encryption
{
	/**
	 * 모듈 설정 화면을 표시하는 메소드.
	 */
	public function dispEncryptionAdminConfig()
	{
		// 현재 설정을 불러온다.
		Context::set('encryption_config', $this->getConfig());
		
		// mcrypt 및 openssl 모듈을 사용할 수 있는지 확인한다.
		Context::set('encryption_aes_enabled', function_exists('mcrypt_create_iv'));
		Context::set('encryption_rsa_enabled', function_exists('openssl_pkey_new'));
		
		// 템플릿을 지정한다.
		$this->setTemplatePath($this->module_path.'tpl');
		$this->setTemplateFile('config');
	}
}
