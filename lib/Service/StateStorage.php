<?php

declare(strict_types=1);

namespace OCA\TwoFactorEmail\Service;

use Exception;
use OCA\TwoFactorEmail\AppInfo\Application;
use OCA\TwoFactorEmail\Provider\Email as EmailProvider;
use OCA\TwoFactorEmail\Provider\State;
use OCP\IConfig;
use OCP\IUser;
use OCP\IGroupManager;

class StateStorage {

	/** @var IConfig */
	private $config;
	/**
	 * @var IGroupManager
	 */
	private $groupManager;

	public function __construct(IConfig $config,IGroupManager $groupManager) {
		$this->config = $config;
		$this->groupManager = $groupManager;
	}

	private function getUserValue(IUser $user, string $key, $default = ''): string {
		return $this->config->getUserValue($user->getUID(), Application::APP_NAME, $key, $default);
	}

	private function setUserValue(IUser $user, string $key, $value): void {
		$this->config->setUserValue($user->getUID(), Application::APP_NAME, $key, $value);
	}

	private function deleteUserValue(IUser $user, string $key): void {
		$this->config->deleteUserValue($user->getUID(), Application::APP_NAME, $key);
	}
	private function isEnforcement(IUser $user):bool {
		$enforcedGroups = $this->config->getSystemValue('twofactor_enforced_groups', []);
		$userGroups = $this->groupManager->getUserGroups($user);
		foreach($userGroups as $userGroup){
			if(in_array($userGroup->getGID(),$enforcedGroups)){
				return true;
			}
		}
		return false;
	}

	public function get(IUser $user): State {
		$isVerified = $this->getUserValue($user, 'verified', 'false') === 'true';
		$authenticationCode = $this->getUserValue($user, 'authentication_code');
		$isEnforced = $this->isEnforcement($user);

		if ($isVerified) {
			$state = EmailProvider::STATE_ENABLED;
		} elseif ($authenticationCode !== '') {
			$state = EmailProvider::STATE_VERIFYING;
		} else {
			$state = EmailProvider::STATE_DISABLED;
		}

		return new State(
			$user,
			$state,
			$authenticationCode,
			$isEnforced,
		);
	}

	public function persist(State $state): State {
		switch ($state->getState()) {
			case EmailProvider::STATE_DISABLED:
				$this->deleteUserValue(
					$state->getUser(),
					'verified'
				);
				$this->deleteUserValue(
					$state->getUser(),
					'authentication_code'
				);

				break;
			case EmailProvider::STATE_VERIFYING:
				$this->setUserValue(
					$state->getUser(),
					'authentication_code',
					$state->getVerificationCode()
				);
				$this->setUserValue(
					$state->getUser(),
					'verified',
					'false'
				);

				break;
			case EmailProvider::STATE_ENABLED:
				$this->setUserValue(
					$state->getUser(),
					'authentication_code',
					$state->getVerificationCode()
				);
				$this->setUserValue(
					$state->getUser(),
					'verified',
					'true'
				);

				break;
			default:
				throw new Exception('invalid provider state');
		}

		return $state;
	}
}
