<?php

namespace SimpleSAML\Module\oidc\Server\Grants;

use CirrusIdentity\SSP\Utils\MetricLogger;
use DateInterval;
use Exception;
use League\OAuth2\Server\Grant\RefreshTokenGrant as OAuth2RefreshTokenGrant;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class RefreshTokenGrant extends OAuth2RefreshTokenGrant
{
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId)
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (\is_null($encryptedRefreshToken)) {
            throw OidcServerException::invalidGrant('Failed to verify `refresh_token`');
        }

        // Validate refresh token
        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            throw OidcServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
        }

        $refreshTokenData = \json_decode($refreshToken, true);
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OidcServerException::invalidRefreshToken('Token is not linked to client');
        }

        if ($refreshTokenData['expire_time'] < \time()) {
            throw OidcServerException::invalidRefreshToken('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw OidcServerException::invalidRefreshToken('Token has been revoked');
        }

        return $refreshTokenData;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        $responseType = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);

        $client = $this->validateClient($request);
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);

        MetricLogger::getInstance()->logMetric(
            'oidc',
            'token',
            [
                'oldRefreshTokenPrefix' => substr($encryptedRefreshToken, 0, 20),
                'grantType' => $this->getIdentifier(),
                'clientId' => $client->getIdentifier()
            ]
        );

        return $responseType;
    }
}
