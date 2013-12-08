package com.identityconcepts.shibboleth.relyingparty;

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;

/** ECP SAML 2 SSO configuration settings. */
public class WSFedConfiguration extends SSOConfiguration {

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://www.identityconcepts.com.au/idc/idp/wsfed";

    /** {@inheritDoc} */
    public String getProfileId() {
        return PROFILE_ID;
    }
}

