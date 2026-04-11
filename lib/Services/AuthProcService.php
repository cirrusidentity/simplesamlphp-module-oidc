<?php

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Module\oidc\Services\AuthProcService\OidcProcessingChain;
use SimpleSAML\Utils;

class AuthProcService
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var array Filters to be applied to OIDC state.
     */
    private $filters = [];

    /**
     * AuthProcService constructor.
     * @param ConfigurationService $configurationService
     *
     * @throws \Exception
     * @see \SimpleSAML\Auth\ProcessingChain for original implementation
     */
    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
        $this->loadFilters();
    }

    /**
     * Load filters defined in configuration.
     * @throws \Exception
     */
    private function loadFilters(): void
    {
        $oidcAuthProcFilters = $this->configurationService->getAuthProcFilters();
        $this->filters = $this->parseFilterList($oidcAuthProcFilters);
    }

    /**
     * Parse an array of authentication processing filters.
     * @see \SimpleSAML\Auth\ProcessingChain::parseFilterList for original implementation
     *
     * @param array $filterSrc Array with filter configuration.
     * @return array  Array of ProcessingFilter objects.
     * @throws \Exception
     */
    private function parseFilterList(array $filterSrc): array
    {
        $parsedFilters = [];

        foreach ($filterSrc as $priority => $filterConfig) {
            if (is_string($filterConfig)) {
                $filterConfig = ['class' => $filterConfig];
            }

            if (!is_array($filterConfig)) {
                throw new \Exception('Invalid authentication processing filter configuration: ' .
                                     'One of the filters wasn\'t a string or an array.');
            }

            if (!array_key_exists('class', $filterConfig)) {
                throw new \Exception('Authentication processing filter without name given.');
            }

            $className = Module::resolveClass(
                $filterConfig['class'],
                'Auth\Process',
                '\SimpleSAML\Auth\ProcessingFilter'
            );

            $filterConfig['%priority'] = $priority;
            unset($filterConfig['class']);

            /**
             * @psalm-suppress InvalidStringClass
             */
            $parsedFilters[] = new $className($filterConfig, null);
        }

        return $parsedFilters;
    }

    /**
     * Process given state array.
     *
     * @param array $state
     * @return array
     */
    public function processState(array &$state): array
    {
        assert(is_array($state));
        assert(array_key_exists('ReturnURL', $state) || array_key_exists('ReturnCall', $state));
        assert(!array_key_exists('ReturnURL', $state) || !array_key_exists('ReturnCall', $state));

        $state[OidcProcessingChain::FILTERS_INDEX] = $this->filters;

        try {
            while (count($state[OidcProcessingChain::FILTERS_INDEX]) > 0) {
                $filter = array_shift($state[OidcProcessingChain::FILTERS_INDEX]);
                $filter->process($state);
            }
        } catch (Error\Exception $e) {
            // No need to convert the exception
            throw $e;
        } catch (\Exception $e) {
            /*
             * To be consistent with the exception we return after an redirect,
             * we convert this exception before returning it.
             */
            throw new Error\UnserializableException($e);
        }

        return $state;
    }

    /**
     * Get filters loaded from configuration.
     *
     * @return array
     */
    public function getLoadedFilters(): array
    {
        return $this->filters;
    }

    /**
     * Continues processing of the state.
     *
     * This function is used to resume processing by filters which for example needed to show
     * a page to the user.
     *
     * This function will never return. Exceptions thrown during processing will be passed
     * to whatever exception handler is defined in the state array.
     *
     * @param array $state  The state we are processing.
     * @return void
     */
    public static function resumeProcessing(array &$state)
    {
        while (count($state[OidcProcessingChain::FILTERS_INDEX]) > 0) {
            $filter = array_shift($state[OidcProcessingChain::FILTERS_INDEX]);
            try {
                $filter->process($state);
            } catch (Error\Exception $e) {
                State::throwException($state, $e);
            } catch (\Exception $e) {
                $e = new Error\UnserializableException($e);
                State::throwException($state, $e);
            }
        }
        // Completed

        assert(array_key_exists('ReturnURL', $state) || array_key_exists('ReturnCall', $state));
        assert(!array_key_exists('ReturnURL', $state) || !array_key_exists('ReturnCall', $state));

        if (array_key_exists('ReturnURL', $state)) {
            /*
             * Save state information, and redirect to the URL specified
             * in $state['ReturnURL'].
             */
            $id = State::saveState($state, OidcProcessingChain::COMPLETED_STAGE);
            Utils\HTTP::redirectTrustedURL($state['ReturnURL'], [OidcProcessingChain::AUTHPARAM => $id]);
        } else {
            /* Pass the state to the function defined in $state['ReturnCall']. */

            // We are done with the state array in the session. Delete it.
            State::deleteState($state);

            $func = $state['ReturnCall'];
            assert(is_callable($func));

            call_user_func($func, $state);
            assert(false);
        }
    }
}
