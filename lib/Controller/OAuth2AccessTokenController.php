<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Controller;

use Exception;
use CirrusIdentity\SSP\Utils\MetricLogger;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class OAuth2AccessTokenController
{
    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;

    private AllowedOriginRepository $allowedOriginRepository;

    public function __construct(AuthorizationServer $authorizationServer,  AllowedOriginRepository $allowedOriginRepository)
    {
        $this->authorizationServer = $authorizationServer;
        $this->allowedOriginRepository = $allowedOriginRepository;

    }

    public function __invoke(ServerRequest $request): \Psr\Http\Message\ResponseInterface
    {
        // Check if this is actually a CORS preflight request...
        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            try {
                return $this->handleCors($request);
            } catch (OidcServerException $e) {
                MetricLogger::getInstance()->logMetric(
                    'oidc',
                    'error',
                    [
                        'message' => $e->getMessage(),
                        'errorDescription' => $e->getPayload()["error_description"],
                        'oidc' => [
                                'endpoint' => 'token',
                            ]
                    ]
                );

                throw $e;
            }
        }

        try {
            return $this->authorizationServer->respondToAccessTokenRequest($request, new Response());
        } catch (Exception $e) {
            MetricLogger::getInstance()->logMetric(
                'oidc',
                'error',
                [
                    'message' => $e->getMessage(),
                    'oidc' => [
                            'endpoint' => 'token',
                            'clientId' => $this->getClientIdFromTokenRequest($request),
                            'grantType' => $this->getRequestParameter("grant_type", $request)
                        ]

                ]
            );

            throw $e;
        }
    }

    /**
     * Handle CORS 'preflight' requests by checking if 'origin' is registered as allowed to make HTTP CORS requests,
     * typically initiated in browser by JavaScript clients.
     * @param ServerRequest $request
     * @return Response
     * @throws OidcServerException
     */
    protected function handleCors(ServerRequest $request): Response
    {
        $origin = $request->getHeaderLine('Origin');

        if (empty($origin)) {
            throw OidcServerException::requestNotSupported('CORS error: no Origin header present');
        }

        if (! $this->allowedOriginRepository->has($origin)) {
            throw OidcServerException::accessDenied(sprintf('CORS error: origin %s is not allowed', $origin));
        }

        $headers = [
            'Access-Control-Allow-Origin' => $origin,
            'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
            // set X-Requested-With headers
            // TODO: client will send headers in access-control-request-headers, maybe log which ones are not included
            'Access-Control-Allow-Headers' => 'Authorization, X-Requested-With',
            'Access-Control-Allow-Credentials' => 'true',
        ];

        return new Response('php://memory', 204, $headers);
    }

    private function getClientIdFromTokenRequest(ServerRequest $request)
    {
        [$basicAuthUser, $basicAuthPassword] = $this->getBasicAuthCredentials($request);

        $clientId = $this->getRequestParameter('client_id', $request, $basicAuthUser);

        return $clientId;
    }

    private function getBasicAuthCredentials(ServerRequest $request)
    {
        if (!$request->hasHeader('Authorization')) {
            return [null, null];
        }

        $header = $request->getHeader('Authorization')[0];
        if (\strpos($header, 'Basic ') !== 0) {
            return [null, null];
        }

        if (!($decoded = \base64_decode(\substr($header, 6)))) {
            return [null, null];
        }

        if (\strpos($decoded, ':') === false) {
            return [null, null]; // HTTP Basic header without colon isn't valid
        }

        return \explode(':', $decoded, 2);
    }

    private function getRequestParameter($parameter, ServerRequest $request, $default = null)
    {
        $requestParameters = (array) $request->getParsedBody();

        return $requestParameters[$parameter] ?? $default;
    }
}
