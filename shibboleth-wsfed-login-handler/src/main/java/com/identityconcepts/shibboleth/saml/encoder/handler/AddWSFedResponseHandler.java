/*
 * Copyright [2013] [Identity Concepts]
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

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.ecp.Response;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.MessageContextEvaluatingFunctor;
import org.opensaml.ws.message.MessageException;
import org.opensaml.ws.message.handler.Handler;
import org.opensaml.ws.message.handler.HandlerException;
import org.opensaml.ws.soap.util.SOAPHelper;
import org.opensaml.ws.soap.soap11.ActorBearing;
import org.opensaml.xml.Configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;


/**
 * Handler implementation that adds a SAML 2 ecp:Response header to the outbound SOAP envelope.
 */
public class AddWSFedResponseHandler implements Handler {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AddWSFedResponseHandler.class);

    /** Builder of Action object. */
    private SAMLObjectBuilder<Response> responseBuilder;
    
    /** Message context functor which produces the Action value. */
    private MessageContextEvaluatingFunctor<String> acsURLValueSource;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    public AddWSFedResponseHandler() {
        responseBuilder = (SAMLObjectBuilder<Response>) Configuration.getBuilderFactory()
            .getBuilder(Response.DEFAULT_ELEMENT_NAME);
    }
    
    /**
     * Set the functor which produces the AssertionConsumerService URL value from the message context.
     * 
     * @param functor the new message context functor
     */
    public void setACSURLValueSource(MessageContextEvaluatingFunctor<String> functor) {
        acsURLValueSource = functor;
    }

    /** {@inheritDoc} */
    public void invoke(MessageContext msgContext) throws HandlerException {
        String acsURLValue = getACSURLValue(msgContext);
        if (acsURLValue != null) {
            Response response = responseBuilder.buildObject();
            response.setAssertionConsumerServiceURL(acsURLValue);
            
            //TODO generalize for SOAP 1.1 vs. 1.2 etc.  May need to add more SOAP helper support.
            SOAPHelper.addSOAP11MustUnderstandAttribute(response, true);
            SOAPHelper.addSOAP11ActorAttribute(response, ActorBearing.SOAP11_ACTOR_NEXT);
            SOAPHelper.addHeaderBlock(msgContext, response);
        }
    }

    /**
     * Get the value of the AssertionConsumerServiceURL.
     * 
     * @param msgContext  the current message context
     * @return the ACS URL value.
     * 
     * @throws HandlerException if there is a problem obtaining the ACS URL value from the context
     */
    protected String getACSURLValue(MessageContext msgContext) throws HandlerException {
        if (acsURLValueSource != null) {
            try {
                return acsURLValueSource.evaluate(msgContext);
            } catch (MessageException e) {
                throw new HandlerException("Error obtaining AssertionConsumerService URL value from the context", e);
            }
        }
        return null;
    }

}
