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

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Controller\LogoutController;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;

class AuthenticationService
{
    use GetClientFromRequestTrait;

    private UserRepository $userRepository;

    private AuthSimpleFactory $authSimpleFactory;

    private string $userIdAttr;

    private ProcessingChainFactory $processingChainFactory;

    private OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService;

    private SessionService $sessionService;

    /**
     * ID of auth source used during authn.
     */
    private ?string $authSourceId;

    private ClaimTranslatorExtractor $claimTranslatorExtractor;

    public function __construct(
        UserRepository $userRepository,
        AuthSimpleFactory $authSimpleFactory,
        ProcessingChainFactory $processingChainFactory,
        ClientRepository $clientRepository,
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService,
        SessionService $sessionService,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
        string $userIdAttr
    ) {
        $this->userRepository = $userRepository;
        $this->authSimpleFactory = $authSimpleFactory;
        $this->processingChainFactory = $processingChainFactory;
        $this->clientRepository = $clientRepository;
        $this->oidcOpenIdProviderMetadataService = $oidcOpenIdProviderMetadataService;
        $this->sessionService = $sessionService;
        $this->claimTranslatorExtractor = $claimTranslatorExtractor;
        $this->userIdAttr = $userIdAttr;
    }

    /**
     * @param   ServerRequestInterface           $request
     * @param   AuthorizationRequest       $authorizationRequest
     *
     * @return array
     * @throws Error\AuthSource
     * @throws Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws Error\UnserializableException
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function processRequest(
        ServerRequestInterface $request,
        AuthorizationRequest $authorizationRequest
    ): array {
        $oidcClient = $this->getClientFromRequest($request);
        $authSimple = $this->authSimpleFactory->build($oidcClient);

        $this->authSourceId = $authSimple->getAuthSource()->getAuthId();

        if (!$authSimple->isAuthenticated()) {
            $this->authenticate($oidcClient);
        } elseif ($this->sessionService->getIsAuthnPerformedInPreviousRequest()) {
            $this->sessionService->setIsAuthnPerformedInPreviousRequest(false);

            $this->sessionService->registerLogoutHandler(
                $this->authSourceId,
                LogoutController::class,
                'logoutHandler',
            );
        } else {
            $this->sessionService->setIsCookieBasedAuthn(true);
        }

        $state = $this->prepareStateArray($authSimple, $oidcClient, $request, $authorizationRequest);
        $this->runAuthProcs($state);

        return $state;
    }

    /**
     * This is a wrapper around Auth/State::loadState that facilitates testing by
     * hiding the static method
     *
     * @param   array  $queryParameters
     *
     * @return array|null
     * @throws NoState
     */
    public function manageState(array $queryParameters): ?array
    {
        if (empty($queryParameters[ProcessingChain::AUTHPARAM])) {
            throw new Error\NoState();
        }

        $stateId = (string)$queryParameters[ProcessingChain::AUTHPARAM];
        $state = State::loadState($stateId, ProcessingChain::COMPLETED_STAGE);

        if (!empty($state['authSourceId'])) {
            $this->authSourceId = (string)$state['authSourceId'];
            unset($state['authSourceId']);
        }

        return $state;
    }

    /**
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws \JsonException
     */
    public function authenticate(
        ClientEntityInterface $clientEntity,
        array $loginParams = []
    ): void {
        $authSimple = $this->authSimpleFactory->build($clientEntity);

        $this->sessionService->setIsCookieBasedAuthn(false);
        $this->sessionService->setIsAuthnPerformedInPreviousRequest(true);

        $authSimple->login($loginParams);
    }

    /**
     * @param ServerRequestInterface $request
     * @param array $loginParams
     * @param bool $forceAuthn
     * @return UserEntity
     * @throws Error\Exception
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Exception
     */
    public function getAuthenticateUser(
        ?array $state
    ): UserEntity {
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            throw new Error\Exception('State array does not contain any attributes.');
        }

        $claims = $state['Attributes'];

        if (!array_key_exists($this->userIdAttr, $claims)) {
            $attr = implode(', ', array_keys($claims));
            throw new Error\Exception(
                'Attribute `useridattr` doesn\'t exists in claims. Available attributes are: ' . $attr
            );
        }

        $userId = $claims[$this->userIdAttr][0];
        $user = $this->userRepository->getUserEntityByIdentifier($userId);

        if (!$user) {
            $user = UserEntity::fromData($userId, $claims);
            $this->userRepository->add($user);
        } else {
            $user->setClaims($claims);
            $this->userRepository->update($user);
        }

        if (empty($state['Oidc']['RelyingPartyMetadata']['id'])) {
            throw new Error\Exception('OIDC RelyingPartyMetadata ID does not exist in state.');
        }

        $oidcClient = $this->clientRepository->findById((string)$state['Oidc']['RelyingPartyMetadata']['id']);
        if (!$oidcClient) {
            throw new Error\Exception('Client not found.');
        }
        $this->addRelyingPartyAssociation($oidcClient, $user);

        return $user;
    }

    /**
     * @param   array|null  $state
     *
     * @return AuthorizationRequest
     * @throws Exception
     */

    public function getAuthorizationRequestFromState(?array $state): AuthorizationRequest
    {
        if (!isset($state['authorizationRequest'])) {
            throw new Exception('Authorization Request is not set.');
        }

        if ($state['authorizationRequest'] instanceof AuthorizationRequest) {
            return $state['authorizationRequest'];
        } else {
            throw new Exception('Authorization Request is not valid.');
        }
    }

    /**
     * @param Simple $authSimple
     * @param ClientEntityInterface $client
     * @param ServerRequestInterface $request
     * @param AuthorizationRequest $authorizationRequest
     * @return array
     */
    public function prepareStateArray(
        Simple $authSimple,
        ClientEntityInterface $client,
        ServerRequestInterface $request,
        AuthorizationRequest $authorizationRequest
    ): array {
        $state = $authSimple->getAuthDataArray();

        $state['Oidc'] = [
            'OpenIdProviderMetadata' => $this->oidcOpenIdProviderMetadataService->getMetadata(),
            'RelyingPartyMetadata' => array_filter($client->toArray(), function (string $key) {
                return $key !== 'secret';
            }, ARRAY_FILTER_USE_KEY),
            'AuthorizationRequestParameters' => array_filter($request->getQueryParams(), function (string $key) {
                $relevantAuthzParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'code_challenge_method'];
                return in_array($key, $relevantAuthzParams);
            }, ARRAY_FILTER_USE_KEY),
        ];

        // Source and destination entity IDs, useful for eg. F-ticks logging...
        $state['Source'] = ['entityid' => $state['Oidc']['OpenIdProviderMetadata']['issuer']];
        $state['Destination'] = ['entityid' => $state['Oidc']['RelyingPartyMetadata']['id']];

        $state[State::RESTART] = $request->getUri()->__toString();

        // Data required after we get back from a ProcessingChain redirect
        $state['authorizationRequest'] = $authorizationRequest;
        $state['authSourceId'] = $authSimple->getAuthSource()->getAuthId();

        return $state;
    }

    public function isCookieBasedAuthn(): bool
    {
        return (bool) $this->sessionService->getIsCookieBasedAuthn();
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSourceId;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionService->getCurrentSession()->getSessionId();
    }

    /**
     * Store Relying Party Association to the current session.
     * @param ClientEntityInterface $oidcClient
     * @param UserEntity $user
     * @throws Exception
     */
    protected function addRelyingPartyAssociation(ClientEntityInterface $oidcClient, UserEntity $user): void
    {
        // We need to make sure that we use 'sub' as user identifier, if configured.
        $claims = $this->claimTranslatorExtractor->extract(['openid'], $user->getClaims());

        $this->sessionService->addRelyingPartyAssociation(
            new RelyingPartyAssociation(
                $oidcClient->getIdentifier(),
                $claims['sub'] ?? $user->getIdentifier(),
                $this->getSessionId(),
                $oidcClient->getBackChannelLogoutUri()
            )
        );
    }

    /**
     * Run authproc filters with the processing chain
     * Creating the ProcessingChain required metadata.
     * - For the idp metadata use the OIDC issuer as the entityId (and the authprocs from the main config file)
     * - For the sp metadata use the client id as the entityId (and don’t set authprocs).
     *
     * @param   array  $state
     *
     * @return void
     * @throws Exception
     * @throws Error\UnserializableException
     * @throws \Exception
     */
    protected function runAuthProcs(array &$state): void
    {
        $configurationService = new ConfigurationService();

        $idpMetadata = [
            'entityid' => $state['Source']['entityid'] ?? '',
            // ProcessChain needs to know the list of authproc filters we defined in module_oidc configuration
            'authproc' => $configurationService->getAuthProcFilters(),
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid'] ?? '',
        ];

        $state['ReturnURL'] = $configurationService->getOpenIdConnectModuleURL('authorization');
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $this->processingChainFactory->build($state)->processState($state);
    }
}
