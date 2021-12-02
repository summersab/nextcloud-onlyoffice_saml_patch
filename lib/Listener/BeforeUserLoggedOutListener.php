<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2021, Andrew Summers
 *
 * @author Andrew Summers
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\OnlyofficeSAMLPatch\Listener;

use OCP\BackgroundJob\IJobList;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserSession;
use OCP\User\Events\BeforeUserLoggedOutEvent;
use OC;

class BeforeUserLoggedOutListener implements IEventListener {
	public function __construct() {
	}

	public function handle(Event $event): void {		
		if ($event instanceof BeforeUserLoggedOutEvent) {
			$timeFactory = new OC\AppFramework\Utility\TimeFactory();

			// Should probably use something like https://github.com/jeremykendall/php-domain-parser to detect compound TLDs like .co.uk
			$ooURL = OC::$server->getAppConfig()->getValue('onlyoffice', 'DocumentServerUrl');
			$ooURLParts = parse_url($ooURL);
			$ooHostParts = explode('.', $ooURLParts['host']);
			$domain = end($ooHostParts);
			$domain = '.' . prev($ooHostParts) . '.' . $domain;

			unset($_COOKIE['onlyoffice_session_data']);
			setcookie('onlyoffice_session_data', '', $timeFactory->getTime() - 3600, $ooURLParts['path'], $domain, false, false);
			setcookie('onlyoffice_session_data', '', $timeFactory->getTime() - 3600, $ooURLParts['path'] . '/', $domain, false, false);
		}		
	}
}