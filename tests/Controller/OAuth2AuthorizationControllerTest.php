<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Error;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Controller\OAuth2AuthorizationController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OAuth2AuthorizationController
 */
class OAuth2AuthorizationControllerTest extends TestCase
{
    /**
     * @var mixed
     */
    protected $authenticationServiceStub;
    /**
     * @var mixed
     */
    protected $authorizationServerStub;
    /**
     * @var mixed
     */
    protected $configurationServiceStub;
    /**
     * @var mixed
     */
    protected $loggerServiceMock;
    /**
     * @var mixed
     */
    protected $authorizationRequestMock;
    /**
     * @var mixed
     */
    protected $userEntityStub;
    /**
     * @var mixed
     */
    protected $serverRequestStub;
    /**
     * @var mixed
     */
    protected $responseStub;

    protected static string $sampleAuthSourceId = 'authSource123';

    protected static array $sampleAuthSourcesToAcrValuesMap = ['authSource123' => ['1', '0']];

    protected static array $sampleRequestedAcrs = ['values' => ['1', '0'], 'essential' => false];

    protected array $state;

    public const USER_ENTITY_ATTRIBUTES = [
        'uid' => ['username'],
        'eduPersonTargetedId' => ['username'],
    ];
    public const AUTH_DATA = ['Attributes' => self::USER_ENTITY_ATTRIBUTES];
    public const CLIENT_ENTITY = ['id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const AUTHZ_REQUEST_PARAMS = ['client_id' => 'clientid', 'redirect_uri' => 'https://rp.example.org'];
    public const OIDC_OP_METADATA = ['issuer' => 'https://idp.example.org'];

    public function setUp(): void
    {
        $this->authenticationServiceStub = $this->createStub(AuthenticationService::class);
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->configurationServiceStub = $this->createStub(ConfigurationService::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->authorizationRequestMock = $this->createMock(AuthorizationRequest::class);
        $this->userEntityStub = $this->createStub(UserEntity::class);
        $this->serverRequestStub = $this->createStub(ServerRequest::class);
        $this->responseStub = $this->createStub(ResponseInterface::class);

        $this->state = [
            'Attributes' => self::AUTH_DATA['Attributes'],
            'Oidc' => [
                'OpenIdProviderMetadata' => self::OIDC_OP_METADATA,
                'RelyingPartyMetadata' => self::CLIENT_ENTITY,
                'AuthorizationRequestParameters' => self::AUTHZ_REQUEST_PARAMS,
            ],
            'authorizationRequest' => $this->authorizationRequestMock,
        ];
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testReturnsResponseWhenInvoked(): void
    {
        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->authenticationServiceStub->method('getAuthenticateUser')->willReturn($this->userEntityStub);

        $controller = new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        );

        $this->assertInstanceOf(ResponseInterface::class, $controller($this->serverRequestStub));
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrThrowsIfAuthSourceIdNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrThrowsIfCookieBasedAuthnNotSetInAuthorizationRequest(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrSetsForcedAcrForCookieAuthentication(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(true);

        $this->configurationServiceStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);
        $this->configurationServiceStub->method('getForcedAcrValueForCookieAuthentication')->willReturn('0');

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('0');

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrThrowsIfNoMatchedAcrForEssentialAcrs(): void
    {
        $requestedAcrs = ['values' => ['a', 'b'], 'essential' => true];
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn($requestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->configurationServiceStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->expectException(OidcServerException::class);

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrSetsFirstMatchedAcr(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->configurationServiceStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrSetsCurrentSessionAcrIfNoMatchedAcr(): void
    {
        $requestedAcrs = ['values' => ['a', 'b'], 'essential' => false];
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn($requestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $this->configurationServiceStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn(self::$sampleAuthSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr')->with('1');

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     */
    public function testValidateAcrLogsWarningIfNoAcrsConfigured(): void
    {
        $this->authorizationRequestMock
            ->method('getRequestedAcrValues')
            ->willReturn(self::$sampleRequestedAcrs);

        $this->authorizationRequestMock->method('getAuthSourceId')->willReturn(self::$sampleAuthSourceId);
        $this->authorizationRequestMock->method('getIsCookieBasedAuthn')->willReturn(false);

        $authSourcesToAcrValuesMap = [self::$sampleAuthSourceId => []];
        $this->configurationServiceStub
            ->method('getAuthSourcesToAcrValuesMap')
            ->willReturn($authSourcesToAcrValuesMap);

        $this->authorizationServerStub
            ->method('validateAuthorizationRequest')
            ->willReturn($this->authorizationRequestMock);
        $this->authorizationServerStub
            ->method('completeAuthorizationRequest')
            ->willReturn($this->responseStub);

        $this->serverRequestStub
            ->method('getQueryParams')
            ->willReturn([ProcessingChain::AUTHPARAM => '123']);

        $this->authenticationServiceStub->method('manageState')
            ->willReturn($this->state);
        $this->authenticationServiceStub
            ->method('getAuthorizationRequestFromState')
            ->willReturn($this->authorizationRequestMock);

        $this->authorizationRequestMock->expects($this->once())->method('setAcr');
        $this->loggerServiceMock->expects($this->once())->method('warning');

        (new OAuth2AuthorizationController(
            $this->authenticationServiceStub,
            $this->authorizationServerStub,
            $this->configurationServiceStub,
            $this->loggerServiceMock
        ))($this->serverRequestStub);
    }
}
