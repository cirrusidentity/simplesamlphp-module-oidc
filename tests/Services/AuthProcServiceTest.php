<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Services\AuthProcService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use PHPUnit\Framework\TestCase;

class AuthProcServiceTest extends TestCase
{
    /** @var ConfigurationService */
    private ConfigurationService $configurationService;

    /** @var array */
    private array $state;

    public function setUp(): void
    {
        putenv('SIMPLESAMLPHP_CONFIG_DIR=' . dirname(__DIR__) . '/config');
        Configuration::clearInternalState();
        unset($GLOBALS['loadCounter']);
        unset($_SERVER['SERVER_NAME']);
        unset($_SERVER['HTTP_HOST']);
        $this->configurationService = new ConfigurationService();
        $this->state = [
            'Attributes' => [
                'urn:oid:0.9.2342.19200300.100.1.1' => '111440182476798224370',
                'urn:oid:2.16.840.1.113730.3.1.241' => 'steve stratus',
                'urn:oid:2.5.4.3' => 'steve stratus',
                'urn:oid:2.5.4.42' => 'steve',
                'urn:oid:2.5.4.4' => 'stratus',
                'urn:oid:0.9.2342.19200300.100.1.3' => 'steve.cirrus.stratus@gmail.com',
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => '111440182476798224370@google.com',
                'extraId' => 'customAttr',
            ],
        ];
    }

    protected function tearDown(): void
    {
        Configuration::clearInternalState();
        putenv('SUPPRESS_CONFIG_LOG=');
    }

    public function testEmptyAuthProc(): void
    {
        $this->runAuthProcs($this->state);

        $expectedAttrs = [
            'urn:oid:0.9.2342.19200300.100.1.1' => '111440182476798224370',
            'urn:oid:2.16.840.1.113730.3.1.241' => 'steve stratus',
            'urn:oid:2.5.4.3' => 'steve stratus',
            'urn:oid:2.5.4.42' => 'steve',
            'urn:oid:2.5.4.4' => 'stratus',
            'urn:oid:0.9.2342.19200300.100.1.3' => 'steve.cirrus.stratus@gmail.com',
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => '111440182476798224370@google.com',
            'eduPersonPrincipalName' => '111440182476798224370@google.com',
            'extraId' => 'customAttr',            
        ];
        $this->assertEquals($expectedAttrs, $this->state['Attributes']);
    }

    private function runAuthProcs(
        array &$state
    ) {
        $aps = new AuthProcService($this->configurationService);

        $state['ReturnCall'] = array('\SimpleSAML\IdP', 'postAuthProc');

        $aps->processState($state);
    }
}
