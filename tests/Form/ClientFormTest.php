<?php

namespace SimpleSAML\Test\Module\oidc\Form;

use SimpleSAML\Module\oidc\Form\ClientForm;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class ClientFormTest extends TestCase
{
    public function testIncomplete(): void
    {
        $this->markTestIncomplete();
    }

    public function validateOriginProvider(): array
    {
        return [
          ['https://example.com', true],
            // not sure why we accepted trailing . but the form says it does
          ['https://example.com.', true],
          ['https://user:pass@example.com', false],
          ['http://example.com', true],
          ['https://example.com:2020', true],
          ['https://localhost:2020', true],
          ['http://localhost:2020', true],
          ['http://localhost', true],
          ['https://example.com/path', false],
          ['https://example.com:8080/path', false],
        ];
    }


    /**
     * @dataProvider validateOriginProvider
     * @param string $value
     * @return void
     */
    public function testValidateOrigin(string $value, bool $isValid): void
    {
        $clientForm = new ClientForm(new ConfigurationService());
        $clientForm->setValues(['allowed_origin' => $value]);
        $clientForm->validateAllowedOrigin($clientForm);

        $this->assertEquals(!$isValid, $clientForm->hasErrors(), $value);
    }
}
