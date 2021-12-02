<?php
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

namespace OCA\OnlyofficeSAMLPatch\Middleware;

use OCP\AppFramework\Middleware;
use OCP\AppFramework\Http\Response;
use OCA\Onlyoffice\Controller\CallbackController;
use OCA\Onlyoffice\Controller\EditorController;
use OCA\Onlyoffice\Controller\FederationController;
use OCA\Onlyoffice\Controller\SettingsController;
use OCA\Onlyoffice\Controller\TemplateController;
use OC;

class OnlyofficeMiddleware extends Middleware {
	public function __construct() {
	}

	public function beforeOutput($controller, $methodName, $output){
		if (
			$controller instanceof CallbackController ||
			$controller instanceof EditorController ||
			$controller instanceof FederationController ||
			$controller instanceof SettingsController ||
			$controller instanceof TemplateController			
		) {
			$jwtSecret = OC::$server->getAppConfig()->getValue('onlyoffice', 'jwt_secret');

			if (
				! OC::$server->getRequest()->getCookie('onlyoffice_session_data') &&
				OC::$server->getAppConfig()->hasKey('onlyoffice', 'jwt_secret') &&
				OC::$server->getRequest()->getCookie('oc_sessionPassphrase') &&
				OC::$server->getRequest()->getCookie(OC::$server->getConfig()->getSystemValue('instanceid'))
			) {
				$crypto = OC::$server->getCrypto();
				$timeFactory = new OC\AppFramework\Utility\TimeFactory();
				$jwtSecret = OC::$server->getAppConfig()->getValue('onlyoffice', 'jwt_secret');

				// Should probably use something like https://github.com/jeremykendall/php-domain-parser to detect compound TLDs like .co.uk
				$ooURL = OC::$server->getAppConfig()->getValue('onlyoffice', 'DocumentServerUrl');
				$ooURLParts = parse_url($ooURL);
				$ooHostParts = explode('.', $ooURLParts['host']);
				$domain = end($ooHostParts);
				$domain = '.' . prev($ooHostParts) . '.' . $domain;

				$cookieStr = OC::$server->getRequest()->getHeader('COOKIE');
				$cookieVal = $this->encrypt($cookieStr, $jwtSecret);
				$cookieVal = base64_encode($cookieVal);

				$options = [
					'expires'	=> $timeFactory->getTime() + 3600,
					'path'		=> $ooURLParts['path'],
					'domain'	=> $domain,
					'secure'	=> false,
					'httponly'	=> false,
				];
				
				setcookie(
					'onlyoffice_session_data',
					$cookieVal,
					$options
				);
			}
		}
		return $output;
	}

	public function beforeController($controller, $methodName) {
	}
	public function afterController($controller, $methodName, Response $response): Response {
		return $response;
	}

	public static function encrypt($value, string $passphrase)
	{
		$salt = openssl_random_pseudo_bytes(8);
		$salted = '';
		$dx = '';
		while (strlen($salted) < 48) {
			$dx = md5($dx . $passphrase . $salt, true);
			$salted .= $dx;
		}
		$key = substr($salted, 0, 32);
		$iv = substr($salted, 32, 16);
		$encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
		$data = ["ct" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "s" => bin2hex($salt)];
		return json_encode($data);
	}
}