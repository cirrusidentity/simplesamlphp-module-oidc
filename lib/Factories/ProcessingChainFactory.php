<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class ProcessingChainFactory
{
    /**
     * @var ConfigurationService
     */
    private ConfigurationService $configurationService;

    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
    }

    /**
     * @codeCoverageIgnore
     * @throws \Exception
     */
    public function build(array $state): ProcessingChain
    {
        $idpMetadata = [
            'entityid' => $state['Source']['entityid'] ?? '',
            // ProcessChain needs to know the list of authproc filters we defined in module_oidc configuration
            'authproc' => $this->configurationService->getAuthProcFilters(),
        ];
        $spMetadata = [
            'entityid' => $state['Destination']['entityid'] ?? '',
        ];

        return new ProcessingChain(
            $idpMetadata,
            $spMetadata,
            'oidc',
        );
    }
}
