/*
 * Copyright 2010 University Corporation for Advanced Internet Development, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.identityconcepts.shibboleth.saml.encoder.handler;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.MessageContextEvaluatingFunctor;
import org.opensaml.ws.message.MessageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Functor which extracts the relying party AssertionConsumerService URL from a {@link SAMLMessageContext}.
 */
public class SAMLPeerEntityEndpointLocationExtractor implements MessageContextEvaluatingFunctor<String> {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLPeerEntityEndpointLocationExtractor.class);

    /** {@inheritDoc} */
    public String evaluate(MessageContext msgContext) throws MessageException {
        if (!(msgContext instanceof SAMLMessageContext)) {
            log.warn("Message context was not an instance of SAMLMessageContext");
            return null;
        }
        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) msgContext;
        
        Endpoint endpoint = samlMsgCtx.getPeerEntityEndpoint();
        if (endpoint != null && endpoint.getLocation() != null) {
            return endpoint.getLocation();
        }
        
        log.warn("Peer entity endpoint location not be determined");
        return null;
    }

}
