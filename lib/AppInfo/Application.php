<?php

declare(strict_types=1);


namespace OCA\DkMunicipalOrganisation\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCA\DkMunicipalOrganisation\BackgroundJob\SyncOrganisationsJob;
use OCA\DkMunicipalOrganisation\Service\Configuration;
use OCP\BackgroundJob\IJobList;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;
use Throwable;

// Load the app's vendor autoloader for phpseclib, onelogin/php-saml, etc.
require_once __DIR__ . '/../../vendor/autoload.php';

class Application extends App implements IBootstrap {
	public const APP_ID = 'dkmunicipalorganisation';

	public function __construct() {
		parent::__construct(self::APP_ID);
	}

	public function register(IRegistrationContext $context): void {
	}

	public function boot(IBootContext $context): void {
		// Ensure background job is registered
		$jobList = $context->getServerContainer()->get(IJobList::class);
		if (!$jobList->has(SyncOrganisationsJob::class, null)) {
			$jobList->add(SyncOrganisationsJob::class);
		}

		try {
			$context->injectFn(function (
				IRequest $request,
				IUserSession $userSession,
				IURLGenerator $urlGenerator,
				IConfig $config,
				ISession $session,
				LoggerInterface $logger,
				Configuration $configuration,
				bool $isCLI,
			): void {
				if ($isCLI) {
					return;
				}

				$logFile = \OC::$SERVERROOT . '/data/saml_acs_debug.log';

				// Only handle browser HTML GET requests (avoid breaking DAV/OCS clients)
				if (strtoupper($request->getMethod()) !== 'GET') {
					return;
				}
				$accept = (string)$request->getHeader('Accept');
				if ($accept !== '' && stripos($accept, 'text/html') === false) {
					return;
				}

				// Get path early
				$path = $request->getPathInfo();

				// Handle logout - redirect SAML users to SAML logout
				// This MUST be checked BEFORE the isLoggedIn check, because logout happens while logged in
				if ($path === '/logout') {
					// Check if this user logged in via SAML
					if ($session->exists('dkmo.saml_login')) {
						file_put_contents($logFile, json_encode([
							'timestamp' => date('Y-m-d H:i:s'),
							'action' => 'saml_logout_redirect',
							'userId' => $userSession->getUser() ? $userSession->getUser()->getUID() : null,
						], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

						$logger->debug('Redirecting SAML user to SAML logout', [
							'app' => self::APP_ID,
						]);

						// Build SAML logout URL
						$logoutUrl = $urlGenerator->linkToRouteAbsolute('dkmunicipalorganisation.saml.logout');

						header('Location: ' . $logoutUrl, true, 302);
						exit();
					}
					return;
				}

				// For login page handling, only act when not logged in
				if ($userSession->isLoggedIn()) {
					return;
				}

				// Prevent infinite loop: if we just completed SAML login, don't redirect again
				if ($session->exists('dkmo.saml_login')) {
					$logger->debug('SAML login marker found, not redirecting', [
						'app' => self::APP_ID,
					]);
					return;
				}

				// Only act on /login for SAML redirect
				if ($path !== '/login') {
					return;
				}

				// Check if remember-me cookies are present and VALID
				$ncToken = $request->getCookie('nc_token');
				$ncSessionId = $request->getCookie('nc_session_id');
				$ncUsername = $request->getCookie('nc_username');
				$hasRememberCookies = ($ncToken !== null && $ncSessionId !== null && $ncUsername !== null);

				// If cookies exist, verify the token is actually valid before trusting them
				$cookiesAreValid = false;
				if ($hasRememberCookies && $ncUsername !== null && $ncToken !== null) {
					// Check if token exists in stored tokens for this user
					$storedTokens = $config->getUserKeys($ncUsername, 'login_token');
					$cookiesAreValid = in_array($ncToken, $storedTokens, true);

					if (!$cookiesAreValid && count($storedTokens) > 0) {
						// Cookies exist but token is stale - clear them so user can do fresh SAML login
						file_put_contents($logFile, json_encode([
							'timestamp' => date('Y-m-d H:i:s'),
							'action' => 'stale_cookies_detected',
							'nc_username' => $ncUsername,
							'tokenInCookie' => substr($ncToken, 0, 10) . '...',
							'storedTokensCount' => count($storedTokens),
						], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

						// Clear the stale cookies
						$webroot = \OC::$WEBROOT ?: '/';
						setcookie('nc_username', '', time() - 3600, $webroot);
						setcookie('nc_token', '', time() - 3600, $webroot);
						setcookie('nc_session_id', '', time() - 3600, $webroot);

						// Continue to SAML redirect below
						$hasRememberCookies = false;
					}
				}

				// Debug logging for session state
				file_put_contents($logFile, json_encode([
					'timestamp' => date('Y-m-d H:i:s'),
					'action' => 'boot_check',
					'path' => $path,
					'isLoggedIn' => $userSession->isLoggedIn(),
					'hasRememberCookies' => $hasRememberCookies,
					'cookiesAreValid' => $cookiesAreValid,
					'sessionId' => session_id(),
					'ncSessionId' => $session->getId(),
					'hasSamlMarker' => $session->exists('dkmo.saml_login'),
					'userId' => $userSession->getUser() ? $userSession->getUser()->getUID() : null,
				], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

				// If user has VALID remember-me cookies, try to log them in with cookies
				// and redirect to dashboard - don't just show the login page
				if ($hasRememberCookies && $cookiesAreValid) {
					// Use a lock to prevent parallel cookie login attempts from racing
					$cache = \OC::$server->getMemCacheFactory()->createDistributed('dkmunicipalorganisation');
					$lockKey = 'cookie_login_lock_' . $ncUsername;

					// Check if another request is already processing this login
					if ($cache->get($lockKey) !== null) {
						file_put_contents($logFile, json_encode([
							'timestamp' => date('Y-m-d H:i:s'),
							'action' => 'cookie_login_locked_skip',
							'nc_username' => $ncUsername,
						], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);
						// Another request is handling login, just redirect to dashboard
						$dashboardUrl = $urlGenerator->linkToRouteAbsolute('dashboard.dashboard.index');
						header('Location: ' . $dashboardUrl, true, 302);
						exit();
					}

					// Acquire lock (5 second TTL)
					$cache->set($lockKey, time(), 5);

					file_put_contents($logFile, json_encode([
						'timestamp' => date('Y-m-d H:i:s'),
						'action' => 'attempting_cookie_login',
						'nc_username' => $ncUsername,
					], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

					// Try to login with the valid cookie
					if ($userSession instanceof \OC\User\Session) {
						$loginResult = $userSession->loginWithCookie($ncUsername, $ncToken, $ncSessionId);

						if ($loginResult) {
							// Successfully logged in - mark as SAML user
							$session->set('dkmo.saml_login', true);
							$session->set('dkmo.user_id', $ncUsername);

							// NOTE: loginWithCookie already creates a new remember-me token
							// Do NOT call createRememberMeToken here - it would create duplicates

							file_put_contents($logFile, json_encode([
								'timestamp' => date('Y-m-d H:i:s'),
								'action' => 'cookie_login_success',
								'nc_username' => $ncUsername,
							], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

							// Release lock
							$cache->remove($lockKey);

							// Redirect to dashboard
							$dashboardUrl = $urlGenerator->linkToRouteAbsolute('dashboard.dashboard.index');
							header('Location: ' . $dashboardUrl, true, 302);
							exit();
						} else {
							file_put_contents($logFile, json_encode([
								'timestamp' => date('Y-m-d H:i:s'),
								'action' => 'cookie_login_failed',
								'nc_username' => $ncUsername,
							], JSON_PRETTY_PRINT) . "\n\n", FILE_APPEND);

							// Release lock
							$cache->remove($lockKey);

							// Cookie login failed - clear cookies and continue to SAML
							$webroot = \OC::$WEBROOT ?: '/';
							setcookie('nc_username', '', time() - 3600, $webroot);
							setcookie('nc_token', '', time() - 3600, $webroot);
							setcookie('nc_session_id', '', time() - 3600, $webroot);
						}
					} else {
						// Can't access Session class, just return and let NC handle it
						$cache->remove($lockKey);
						return;
					}
				}

				// Bypass for admins (your requirement)
				// Note: getParams() can throw LogicException for some methods, but we are GET so OK.
				$params = $request->getParams();
				if (isset($params['direct']) && ($params['direct'] === 1 || $params['direct'] === '1')) {
					return;
				}

				// Only redirect to SAML login when access control is enabled
				$accessControlEnabled = $configuration->getConfigValue('access_control_enable', '0');
				if ($accessControlEnabled !== '1') {
					return;
				}

				// Preserve redirect_url if present (Nextcloud uses this)
				$redirectUrl = '';
				if (isset($params['redirect_url']) && is_string($params['redirect_url'])) {
					$redirectUrl = $params['redirect_url'];
				}

				// For a simple GET redirect to your /saml/login, CSRF token is not strictly necessary.
				// If needed later, it can be obtained from the server container.
				$targetUrl = $urlGenerator->linkToRouteAbsolute(
					'dkmunicipalorganisation.saml.login', // <— matches your controller route name (see below)
					[
						'redirect_url' => $redirectUrl,
					]
				);

				$logger->debug('Auto-redirecting /login to SAML login', [
					'app' => self::APP_ID,
					'path' => $path,
				]);

				header('Location: ' . $targetUrl, true, 302);
				exit();
			});
		} catch (Throwable $e) {
			// Never take the whole instance down if your app fails
			\OC::$server->get(LoggerInterface::class)->critical('Error when loading dkmunicipalorganisation app', [
				'exception' => $e,
			]);
		}
	}
}
