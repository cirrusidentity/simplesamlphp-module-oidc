<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Uri;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use ReflectionClass;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NoState;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\ProcessingChainFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Session;

class AuthenticationServiceTest extends TestCase
{
    public const URI = 'https://some-server/authorize.php?abc=efg';
    public const AUTH_SOURCE = 'auth_source';
    public const USER_ID_ATTR = 'uid';
    public const USERNAME = 'username';
    public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];
    public const USER_ENTITY_ATTRIBUTES = [
        self::USER_ID_ATTR    => [self::USERNAME],
        'eduPersonTargetedId' => [self::USERNAME],
    ];
    public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const STATE = [
        'Attributes' => self::AUTH_DATA['Attributes'],
        'Oidc'       => [
            'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
            'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
            'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
        ],
    ];
    protected MockObject $authSimpleFactoryMock;
    protected MockObject $authSimpleMock;
    protected MockObject $authSourceMock;
    protected MockObject $authorizationRequestMock;
    protected MockObject $claimTranslatorExtractorMock;
    protected MockObject $clientEntityMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $opMetadataService;
    protected MockObject $processingChainFactoryMock;
    protected MockObject $processingChainMock;
    protected MockObject $serverRequestMock;
    protected MockObject $sessionMock;
    protected MockObject $sessionServiceMock;
    protected MockObject $userEntityMock;
    protected MockObject $userRepositoryMock;
    protected string $previousConfigDir;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        $this->authSimpleFactoryMock                 = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleMock                        = $this->createMock(Simple::class);
        $this->authSourceMock                        = $this->createMock(Source::class);
        $this->authorizationRequestMock              = $this->createMock(AuthorizationRequest::class);
        $this->claimTranslatorExtractorMock          = $this->createMock(ClaimTranslatorExtractor::class);
        $this->clientEntityMock                      = $this->createMock(ClientEntity::class);
        $this->clientRepositoryMock                  = $this->createMock(ClientRepository::class);
        $this->processingChainFactoryMock            = $this->createMock(ProcessingChainFactory::class);
        $this->opMetadataService                     = $this->createMock(OidcOpenIdProviderMetadataService::class);
        $this->processingChainMock                   = $this->createMock(ProcessingChain::class);
        $this->serverRequestMock                     = $this->createMock(ServerRequest::class);
        $this->sessionMock                           = $this->createMock(Session::class);
        $this->sessionServiceMock                    = $this->createMock(SessionService::class);
        $this->userEntityMock                        = $this->createMock(UserEntity::class);
        $this->userRepositoryMock                    = $this->createMock(UserRepository::class);

        $this->authSourceMock->method('getAuthId')->willReturn(self::AUTH_SOURCE);
        $this->authSimpleFactoryMock->method('build')->willReturn($this->authSimpleMock);
        $this->authSimpleMock->method('getAttributes')->willReturn(self::AUTH_DATA['Attributes']);
        $this->authSimpleMock->method('getAuthDataArray')->willReturn(self::AUTH_DATA);
        $this->authSimpleMock->method('getAuthSource')->willReturn($this->authSourceMock);
        $this->clientEntityMock->method('getAuthSourceId')->willReturn(self::AUTH_SOURCE);
        $this->clientEntityMock->method('toArray')->willReturn(self::CLIENT_ENTITY);
        $this->opMetadataService->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);
        $this->processingChainFactoryMock->method('build')->willReturn($this->processingChainMock);
        $this->serverRequestMock->method('getQueryParams')->willReturn(self::AUTHZ_REQUEST_PARAMS);
        $this->serverRequestMock->method('getUri')->willReturn(new Uri(self::URI));
        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);
    }

    /**
     * @return AuthenticationService
     */
    public function mock(): AuthenticationService
    {
        return $this->getMockBuilder(AuthenticationService::class)
            ->disableArgumentCloning()
            ->enableOriginalConstructor()
            ->setConstructorArgs(
                [
                     $this->userRepositoryMock,
                     $this->authSimpleFactoryMock,
                     $this->processingChainFactoryMock,
                     $this->clientRepositoryMock,
                     $this->opMetadataService,
                     $this->sessionServiceMock,
                     $this->claimTranslatorExtractorMock,
                     self::USER_ID_ATTR,
                ],
            )->onlyMethods([])
            ->getMock();
    }

    /**
     * @return void
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthenticationService::class,
            $this->mock(),
        );
    }

    /**
     * @return void
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     */
    public function testItCreatesNewUser(): void
    {
        $clientId = 'client123';
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);

        $this->userEntityMock->method('getIdentifier')->willReturn(self::USERNAME);
        $this->userEntityMock->method('getClaims')->willReturn(self::USER_ENTITY_ATTRIBUTES);

        $userEntity = $this->mock()->getAuthenticateUser(self::STATE);

        $this->assertSame(
            $userEntity->getIdentifier(),
            self::USERNAME,
        );
        $this->assertSame(
            $userEntity->getClaims(),
            self::USER_ENTITY_ATTRIBUTES,
        );
    }

    /**
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \JsonException
     */
    public function testItReturnsAnUser(): void
    {
        $clientId = 'client123';
        $userId   = 'user123';

        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn($clientId);
        $this->clientEntityMock->expects($this->once())->method('getBackChannelLogoutUri')->willReturn(null);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->userEntityMock->expects($this->once())->method('getIdentifier')->willReturn($userId);
        $this->userEntityMock->expects($this->once())->method('setClaims')->with(self::USER_ENTITY_ATTRIBUTES);
        $this->userEntityMock->expects($this->once())->method('getClaims')->willReturn([]);

        $this->userRepositoryMock->expects($this->once())->method('getUserEntityByIdentifier')
            ->willReturn($this->userEntityMock);
        $this->userRepositoryMock->expects($this->once())->method('update')->with($this->userEntityMock);

        $this->claimTranslatorExtractorMock->expects($this->once())->method('extract')
            ->with(['openid'], $this->isType('array'))
            ->willReturn([]);

        $this->assertSame(
            $this->mock()->getAuthenticateUser(self::STATE),
            $this->userEntityMock,
        );
    }

    /**
     * @return void
     * @throws Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     */
    public function testGetAuthenticateUserItThrowsIfClaimsNotExist(): void
    {
        $invalidState = self::STATE;
        unset($invalidState['Attributes'][self::USER_ID_ATTR]);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches("/Attribute `useridattr` doesn't exists in claims. Available attributes are: eduPersonTargetedId/");

        $this->mock()->getAuthenticateUser($invalidState);
    }

    /**
     * @return void
     * @throws \JsonException
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     */
    public function testItAuthenticates(): void
    {
        $this->authSimpleMock->expects($this->once())->method('login')->with([]);

        /** @var ClientEntityInterface $client */
        $client = $this->clientEntityMock;

        $this->mock()->authenticate($client);
    }

    /**
     * @return void
     * @throws \SimpleSAML\Error\AuthSource
     */
    public function testItConstructsStateArray(): void
    {
        $state                         = self::STATE;
        $state['Source']               = [
            'entityid' => $state['Oidc']['OpenIdProviderMetadata']['issuer'],
        ];
        $state['Destination']          = [
            'entityid' => $state['Oidc']['RelyingPartyMetadata']['id'],
        ];
        $state[State::RESTART]         = self::URI;
        $state['authorizationRequest'] = $this->authorizationRequestMock;
        $state['authSourceId']         = self::AUTH_SOURCE;

        /** @var Simple */
        $authSimple = $this->authSimpleMock;
        /** @var ClientEntityInterface */
        $client = $this->clientEntityMock;
        /** @var ServerRequestInterface */
        $request = $this->serverRequestMock;
        /** @var AuthorizationRequest */
        $authorizationRequest = $this->authorizationRequestMock;
        $this->assertSame(
            $state,
            $this->mock()->prepareStateArray(
                $authSimple,
                $client,
                $request,
                $authorizationRequest
            ),
        );
    }

    /**
     * @return array
     */
    public static function isAuthnPerformedInPreviousRequest(): array
    {
        return [
            [false],
            [true],
        ];
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \JsonException
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\UnserializableException
     * @dataProvider isAuthnPerformedInPreviousRequest
     */
    public function testItProcessesRequest(bool $isAuthnPer): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $authenticationServiceMock = $this->getMockBuilder(AuthenticationService::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                     $this->userRepositoryMock,
                     $this->authSimpleFactoryMock,
                     $this->processingChainFactoryMock,
                     $this->clientRepositoryMock,
                     $this->opMetadataService,
                     $this->sessionServiceMock,
                     $this->claimTranslatorExtractorMock,
                     self::USER_ID_ATTR
            ])
            ->onlyMethods(['runAuthProcs', 'prepareStateArray'])
            ->getMock();

        $this->authSimpleMock->expects($this->once())->method('isAuthenticated')->willReturn(true);
        $authenticationServiceMock->method('prepareStateArray')->with(
            $this->authSimpleMock,
            $this->clientEntityMock,
            $this->serverRequestMock,
            $this->authorizationRequestMock,
        )->willReturn(self::STATE);

        $this->sessionServiceMock->method('getIsAuthnPerformedInPreviousRequest')->willReturn($isAuthnPer);

        /** @var ServerRequestInterface */
        $request = $this->serverRequestMock;
        /** @var AuthorizationRequest */
        $authorizationRequest = $this->authorizationRequestMock;

        $this->assertSame(
            $authenticationServiceMock->processRequest(
                $request,
                $authorizationRequest,
            ),
            self::STATE,
        );
    }

    /**
     * @throws NoState
     */
    public function testItThrowsOnMissingQueryParameterAuthparam(): void
    {
        $this->expectException(Error\NoState::class);
        $this->mock()->manageState([]);
    }

    /**
     * @return void
     */
    public function testItRunAuthProcs(): void
    {
        $authProcFilters = [
            25 => [
                'class' => 'core:AttributeMap',
                'oid2name',
            ],
        ];
        $returnUrl       = 'http://localhost/simplesaml/module.php/oidc/authorize.php';

        $reflectedAuthService = new ReflectionClass('SimpleSAML\Module\oidc\Services\AuthenticationService');
        $runAuthProcs = $reflectedAuthService->getMethod('runAuthProcs');
        $runAuthProcs->setAccessible(true);

        $authService = $this->mock();

        $state = self::STATE;
        $runAuthProcs->invokeArgs($authService, [&$state]);

        $this->assertEquals($returnUrl, $state['ReturnURL']);
        $this->assertEquals($authProcFilters, $state['Source']['authproc']);
    }

    public function testItGetsAuthorizationRequestFromState(): void
    {
        $authorizationRequest = new AuthorizationRequest();
        $state = self::STATE + ['authorizationRequest' => $authorizationRequest];

        $this->assertEquals(
            $this->mock()->getAuthorizationRequestFromState($state),
            $authorizationRequest,
        );

        $this->assertInstanceOf(
            AuthorizationRequest::class,
            $authorizationRequest,
        );
    }

    /**
     * @return array
     */
    public static function authorizationRequestValues(): array
    {
        return [
            [
                [
                    'authorizationRequest' => 'invalid',
                ],
                '/Authorization Request is not valid./',
            ],
            [
                [],
                '/Authorization Request is not set./',
            ],
        ];
    }

    /**
     * @param   array  $state
     * @param string $exceptionMessage
     *
     * @dataProvider authorizationRequestValues
     * @return void
     * @throws Exception
     */
    public function testGetsAuthorizationRequestFromStateThrowsOnInvalid(array $additionalState, string $exceptionMessage): void
    {
        $state = array_merge(self::STATE, $additionalState);
        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches($exceptionMessage);
        $this->mock()->getAuthorizationRequestFromState($state);
    }

    /**
     * @return array
     */
    public static function getUserState(): array
    {
        return [
            'No Attributes'                   => [
                [
                    'Oidc' => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
                Exception::class,
                '/State array does not contain any attributes./',
            ],
            'No OIDC RelyingPartyMetadata ID' => [
                [
                    'Attributes' => self::AUTH_DATA['Attributes'],
                    'Oidc'       => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
                Exception::class,
                '/OIDC RelyingPartyMetadata ID does not exist in state./',
            ],
            'No Client'                       => [
                [
                    'Attributes' => self::AUTH_DATA['Attributes'],
                    'Oidc'       => [
                        'OpenIdProviderMetadata'         => self::OIDC_OP_METADATA,
                        'RelyingPartyMetadata'           => self::CLIENT_ENTITY,
                        'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
                    ],
                ],
                Exception::class,
                '/Client not found./',
            ],
        ];
    }

    /**
     * @param array $state
     * @param string $exceptionClass
     * @param string $exceptionMessage
     *
     * @dataProvider getUserState
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     */
    public function testGetAuthenticateUserItThrowsWhenState(
        array $state,
        string $exceptionClass,
        string $exceptionMessage
    ): void {
        if (isset($state['Attributes'])) {
            // Needed for the 3rd use case
            $this->clientRepositoryMock->method('findById')->willReturn(null);
        }
        $this->expectException($exceptionClass);
        $this->expectExceptionMessageMatches($exceptionMessage);
        $this->mock()->getAuthenticateUser($state);
    }
}
