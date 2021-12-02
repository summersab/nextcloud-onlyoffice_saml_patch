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

namespace OCA\OnlyofficeSAMLPatch\AppInfo;

use OCA\OnlyofficeSAMLPatch\Listener\BeforeUserLoggedOutListener;
use OCA\OnlyofficeSAMLPatch\Middleware\OnlyofficeMiddleware;
use OC_App;
use OCP\AppFramework\QueryException;
use OC\AppFramework\DependencyInjection\DIContainer;
use OCP\User\Events\BeforeUserLoggedOutEvent;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\AppFramework\Utility\IControllerMethodReflector;
use OCP\IRequest;
use OC;

class Application extends App implements IBootstrap {

	public const APP_ID = 'onlyoffice_saml_patch';

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_ID, $urlParams);

		// Registers the middleware
		foreach (OC_App::getEnabledApps() as $appId) {
			if ($appId == 'onlyoffice') {
				try {
					$appContainer = OC::$server->getRegisteredAppContainer($appId);
				}
				catch (QueryException $e) {
					OC::$server->registerAppContainer($appId, new DIContainer($appId));
					$appContainer = OC::$server->getRegisteredAppContainer($appId);	
				}

				$appContainer->registerService('OnlyofficeMiddleware', function($c){
					return new OnlyofficeMiddleware(
						$c->get(IRequest::class),
						$c->get(IControllerMethodReflector::class)
					);
				});
				$appContainer->registerMiddleware('OnlyofficeMiddleware');
			}
		}
	}

	public function register(IRegistrationContext $context): void {
		$context->registerEventListener(BeforeUserLoggedOutEvent::class, BeforeUserLoggedOutListener::class);
	}

	public function boot(IBootContext $context): void {
	}
}
