<?php

declare(strict_types=1);

namespace OCA\TwoFactorEmail\Provider;

use OCA\TwoFactorEmail\EmailMask;
use OCA\TwoFactorEmail\AppInfo\Application;
use OCA\TwoFactorEmail\Service\Email as EmailService;
use OCA\TwoFactorEmail\Service\StateStorage;
use OCA\TwoFactorEmail\Settings\PersonalSettings;

use OCP\Authentication\TwoFactorAuth\IPersonalProviderSettings;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IProvidesIcons;
use OCP\Authentication\TwoFactorAuth\IProvidesPersonalSettings;
use OCP\IInitialStateService;
use OCP\IL10N;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Security\ISecureRandom;
use OCP\Template;
use OCP\IConfig;

class Email implements IProvider, IProvidesIcons, IProvidesPersonalSettings {
	public const STATE_DISABLED = 0;
	public const STATE_VERIFYING = 1;
	public const STATE_ENABLED = 2;

	/** @var EmailService */
	public $emailService;

	/** @var StateStorage */
	protected $stateStorage;

	/** @var ISession */
	protected $session;

	/** @var ISecureRandom */
	protected $secureRandom;

	/** @var IL10N */
	protected $l10n;

	/** @var IInitialStateService */
	private $initialStateService;

	/** @var IURLGenerator */
	private $urlGenerator;

	/** @var IConfig */
	private $config;

	public function __construct(EmailService $emailService,
								StateStorage $stateStorage,
								ISession $session,
								ISecureRandom $secureRandom,
								IL10N $l10n,
								IInitialStateService $initialStateService,
								IURLGenerator $urlGenerator,
								IConfig $config
								) {
		$this->emailService = $emailService;
		$this->stateStorage = $stateStorage;
		$this->session = $session;
		$this->secureRandom = $secureRandom;
		$this->l10n = $l10n;
		$this->initialStateService = $initialStateService;
		$this->urlGenerator = $urlGenerator;
		$this->config = $config;
	}

	private function getSessionKey(): string {
		return 'twofactor_email_secret';
	}
	private function getC3gSessionKey(): string {
		return 'twofactor_email_expired';
	}
	private function checkExpiredAndReturn():int {

		if($this->session->exists($this->getC3gSessionKey())){
			$expired = $this->session->get($this->getC3gSessionKey());
			if(time() < $expired){
				return $expired;
			}
		}		
		$expiredTime = $this->config->getSystemValue('twofactor_email_expiredtime',0);
		if($expiredTime == 0||!$expiredTime){
			return 0;
		}
		$this->session->remove($this->getSessionKey());
		$expired = time() + $expiredTime;
		$this->session->set($this->getC3gSessionkey(),$expired);
		return $expired;
		
	}
	private function getSecretFromSession(): string {
		if ($this->session->exists($this->getSessionKey())) {
			return $this->session->get($this->getSessionKey());
		}
		return ''; 
		
	}
	private function generateSecret(): string {
		$secret = $this->secureRandom->generate(6, ISecureRandom::CHAR_DIGITS);
		$this->session->set($this->getSessionKey(), $secret);
		return $secret;
	}
	private function sendSecret(IUser $user,string $secret){
		try {
			$this->emailService->send($user, $secret);
			return true;
		} catch (\Exception $ex) {
			return false;
		}
	}

	/**
	 * Get unique identifier of this 2FA provider
	 */
	public function getId(): string {
		return 'email';
	}

	/**
	 * Get the display name for selecting the 2FA provider
	 */
	public function getDisplayName(): string {
		return $this->l10n->t('Email verification');
	}

	/**
	 * Get the description for selecting the 2FA provider
	 */
	public function getDescription(): string {
		return $this->l10n->t('Authenticate via Email');
	}

	private function getSecret(): string {
		if ($this->session->exists($this->getSessionKey())) {
			return $this->session->get($this->getSessionKey());
		}

		$secret = $this->secureRandom->generate(6, ISecureRandom::CHAR_DIGITS);
		$this->session->set($this->getSessionKey(), $secret);
		return $secret;
	}


	/**
	 * Get the template for rending the 2FA provider view
	 */
	public function getTemplate(IUser $user): Template {
		$expired = $this->checkExpiredAndReturn();
		#$secret = $this->getSecret();
		$secret = $this->getSecretFromSession();
		if(!$secret){
			$secret = $this->generateSecret();
			if(!$this->sendSecret($user,$secret)){
				return new Template('twofactor_email','error');
			 }

		}
		

		#try {
		#	$this->emailService->send($user, $secret);
		#} catch (\Exception $ex) {
		#	return new Template('twofactor_email', 'error');
		#}

		$tmpl = new Template('twofactor_email', 'challenge');
		$tmpl->assign('emailAddress', EmailMask::maskEmail($user->getEMailAddress()));
		return $tmpl;
	}

	/**
	 * Verify the given challenge
	 */
	public function verifyChallenge(IUser $user, string $challenge): bool {
		$expired=$this->checkExpiredAndReturn();
		$valid = $this->session->exists($this->getSessionKey())
			&& $this->session->get($this->getSessionKey()) === $challenge;

		if ($valid) {
			$this->session->remove($this->getSessionKey());
			$this->session->remove($this->getC3gSessionKey());
		}

		return $valid;
	}

	/**
	 * Decides whether 2FA is enabled for the given user
	 */
	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return $this->stateStorage->get($user)->getState() === self::STATE_ENABLED;
	}

	public function getPersonalSettings(IUser $user): IPersonalProviderSettings {
		return new PersonalSettings($this->initialStateService, $this->stateStorage->get($user), $user->getEMailAddress() !== null);
	}

	public function getLightIcon(): String {
		return $this->urlGenerator->imagePath(Application::APP_NAME, 'app.svg');
	}

	public function getDarkIcon(): String {
		return $this->urlGenerator->imagePath(Application::APP_NAME, 'app-dark.svg');
	}
}
