<?php

namespace SimpleSAML\Module\oidc\Services\AuthProcService;

class OidcProcessingChain
{
    /**
     * location of processing chain in state array
     */
    public const FILTERS_INDEX = '\SimpleSAML\Auth\OidcProcessingChain.filters';

    /**
     * The stage we use for completed requests.
     */
    public const COMPLETED_STAGE = '\SimpleSAML\Auth\OidcProcessingChain.completed';

    /**
     * The request parameter we will use to pass the state identifier when we redirect after
     * having completed processing of the state.
     */
    public const AUTHPARAM = 'OidcAuthProcId';
}