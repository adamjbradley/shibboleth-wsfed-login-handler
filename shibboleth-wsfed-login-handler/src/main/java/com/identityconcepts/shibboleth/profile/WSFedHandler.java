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

package com.identityconcepts.shibboleth.profile;

import java.io.StringReader;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.AuthnResponseEndpointSelector;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;
import edu.internet2.middleware.shibboleth.idp.session.Session;

import edu.internet2.middleware.shibboleth.idp.profile.saml2.AbstractSAML2ProfileHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.BaseSAML2ProfileRequestContext;

import org.opensaml.ws.message.handler.BasicHandlerChain;
import org.opensaml.ws.message.handler.Handler;
import org.opensaml.ws.message.handler.HandlerChain;
import org.opensaml.ws.message.handler.HandlerChainResolver;
import org.opensaml.ws.message.handler.HandlerException;
import org.opensaml.ws.message.handler.StaticHandlerChainResolver;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;

import com.identityconcepts.shibboleth.relyingparty.WSFedConfiguration;
import com.identityconcepts.shibboleth.saml.encoder.SAMLEncoderHelper;
import com.identityconcepts.shibboleth.saml.encoder.handler.AddWSFedResponseHandler;
import com.identityconcepts.shibboleth.saml.encoder.handler.SAMLPeerEntityEndpointLocationExtractor;
import com.identityconcepts.shibboleth.soap.encoder.ECPSOAP11Encoder;
import com.identityconcepts.shibboleth.soap.decoder.ECPSOAP11Decoder;

/** WS-Fed Passive Request Profile handler. */

public class WSFedHandler extends AbstractSAML2ProfileHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSFedHandler.class);

    /** Builder of AuthnStatement objects. */
    private SAMLObjectBuilder<AuthnStatement> authnStatementBuilder;

    /** Builder of AuthnContext objects. */
    private SAMLObjectBuilder<AuthnContext> authnContextBuilder;

    /** Builder of AuthnContextClassRef objects. */
    private SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder;

    /** Builder of AuthnContextDeclRef objects. */
    private SAMLObjectBuilder<AuthnContextDeclRef> authnContextDeclRefBuilder;

    /** Builder of SubjectLocality objects. */
    private SAMLObjectBuilder<SubjectLocality> subjectLocalityBuilder;

    /** Builder of Endpoint objects. */
    private SAMLObjectBuilder<Endpoint> endpointBuilder;

    /** Static outbound handler chain resolver. */
    private StaticHandlerChainResolver outboundHandlerChainResolver;

    /** Liberty SOAP message encoder to use. */
    private SAMLMessageEncoder messageEncoder;
    private SAMLMessageDecoder messageDecoder;

    // canned soap fauilt
    private static String soapFaultResponseMessage =
"<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
" <env:Body>" +
" <env:Fault>" +
" <faultcode>env:Client</faultcode>" +
" <faultstring>MESSAGE</faultstring>" +
" <detail/>" +
" </env:Fault>" +
" </env:Body>" +
"</env:Envelope>";


    /**
     * Constructor.
     * 
     */
    @SuppressWarnings("unchecked")
    public WSFedHandler() {
        super();

        authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) getBuilderFactory().getBuilder(
                AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) getBuilderFactory().getBuilder(
                AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) getBuilderFactory().getBuilder(
                AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextDeclRefBuilder = (SAMLObjectBuilder<AuthnContextDeclRef>) getBuilderFactory().getBuilder(
                AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
        subjectLocalityBuilder = (SAMLObjectBuilder<SubjectLocality>) getBuilderFactory().getBuilder(
                SubjectLocality.DEFAULT_ELEMENT_NAME);
        endpointBuilder = (SAMLObjectBuilder<Endpoint>) getBuilderFactory().getBuilder(
                AssertionConsumerService.DEFAULT_ELEMENT_NAME);
    }

    /** Initialize the profile handler. */
    public void initialize() {
        outboundHandlerChainResolver = new StaticHandlerChainResolver(buildOutboundHandlerChain());
        messageEncoder = new ECPSOAP11Encoder();
        // we're not using a custom decoder for now
        //messageDecoder = new HandlerChainAwareHTTPSOAP11Decoder();
        // inboundHandlerChainResolver = new StaticHandlerChainResolver(buildInboundHandlerChain());
    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return WSFedConfiguration.PROFILE_ID;
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        // no authn loop - user is already authenticated 
        completeAuthenticationRequest(inTransport, outTransport);
    }
    
    /** {@inheritDoc} */
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
    }
    
    /**
	 * Creates a response to the {@link AuthnRequest} and sends the user, with response in tow, back to the relying
	 * party after they've been authenticated.
	 * 
	 * @param inTransport inbound message transport
	 * @param outTransport outbound message transport
	 * 
	 * @throws ProfileException thrown if the response can not be created and sent back to the relying party
	 */
	protected void completeAuthenticationRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
	        throws ProfileException {
	    HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
	
	    WSFedRequestContext requestContext = buildRequestContext(inTransport, outTransport);
	
	    Response samlResponse;
	
	    try {
	        decodeRequest(requestContext, inTransport, outTransport);
	        checkSamlVersion(requestContext);
	
	        String user = httpRequest.getRemoteUser().replaceFirst("@.*","");
	        log.debug("Setting principal name: " +user+ " ("+ httpRequest.getRemoteUser()+")");
	        requestContext.setPrincipalName(user);
	
	        if (requestContext.getSubjectNameIdentifier() != null) {
	            log.debug("Authentication request contained a subject with a name identifier, resolving principal from NameID");
	            String authenticatedName = requestContext.getPrincipalName();
	            resolvePrincipal(requestContext);
	            String requestedPrincipalName = requestContext.getPrincipalName();
	            if (!DatatypeHelper.safeEquals(authenticatedName, requestedPrincipalName)) {
	                log.warn(
	                        "Authentication request identified principal {} but authentication mechanism identified principal {}",
	                        requestedPrincipalName, authenticatedName);
	                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI,
	                        null));
	                throw new ProfileException("User failed authentication");
	            }
	        }
	
	        String relyingPartyId = requestContext.getInboundMessageIssuer();
	        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
	        ProfileConfiguration ecpConfig = rpConfig.getProfileConfiguration(getProfileId());
	        if (ecpConfig == null) {
	            log.warn("SAML2ECP profile is not configured for relying party '{}'", requestContext.getInboundMessageIssuer());
	            throw new ProfileException("SAML2ECP profile is not configured for relying party");
	        }
	
	        resolveAttributes(requestContext);
	        
	        ArrayList<Statement> statements = new ArrayList<Statement>();
	        statements.add(buildAuthnStatement(requestContext));
	        if (requestContext.getProfileConfiguration().includeAttributeStatement()) {
	            AttributeStatement attributeStatement = buildAttributeStatement(requestContext);
	            if (attributeStatement != null) {
	                requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());
	                statements.add(attributeStatement);
	            }
	        }
	
	        samlResponse = buildResponse(requestContext, "urn:oasis:names:tc:SAML:2.0:cm:bearer", statements);
	        samlResponse.setDestination(requestContext.getPeerEntityEndpoint().getLocation());
	
	    } catch (ProfileException e) {
	
	        // send a soap fault
	        log.debug("sending soap error: " +  e);
	        try {
	           String msg = e.getMessage();
	           if (msg==null) msg = "";
	           outTransport.setCharacterEncoding("UTF-8");
	           outTransport.setHeader("Content-Type", "application/soap+xml");
	           // outTransport.setStatusCode(500);  // seem to lose the message when we report an error.
	           Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
	           out.write(soapFaultResponseMessage.replaceAll("MESSAGE", msg));
	           out.flush();
	        } catch (Exception we) {
	           log.error("error writing soap error: " +  we);
	        }
	        return;
	    }
	
	    requestContext.setOutboundSAMLMessage(samlResponse);
	    requestContext.setOutboundSAMLMessageId(samlResponse.getID());
	    requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
	    encodeResponse(requestContext);
	    writeAuditLogEntry(requestContext);
	}

	/**
	 * Decodes an incoming request and stores the information in a created request context.
	 * 
	 * @param inTransport inbound transport
	 * @param outTransport outbound transport
	 * @param requestContext request context to which decoded information should be added
	 * 
	 * @throws ProfileException thrown if the incoming message failed decoding
	 */
	protected void decodeRequest(WSFedRequestContext requestContext, HTTPInTransport inTransport,
	        HTTPOutTransport outTransport) throws ProfileException {
	    if (log.isDebugEnabled()) {
	        log.debug("Decoding message with decoder binding '{}'", getInboundMessageDecoder(requestContext)
	                .getBindingURI());
	    }
	
	    requestContext.setCommunicationProfileId(getProfileId());
	    requestContext.setMetadataProvider(getMetadataProvider());
	    requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());
	    requestContext.setCommunicationProfileId(getProfileId());
	    requestContext.setInboundMessageTransport(inTransport);
	    requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
	    requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
	    requestContext.setOutboundMessageTransport(outTransport);
	    requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
	
	    try {
	        SAMLMessageDecoder decoder = getInboundMessageDecoder(requestContext);
	        requestContext.setMessageDecoder(decoder);
	        decoder.decode(requestContext);
	        log.debug("Decoded request from relying party '{}'", requestContext.getInboundMessageIssuer());
	
	        if (!(requestContext.getInboundSAMLMessage() instanceof AuthnRequest)) {
	            log.warn("Incomming message was not a AuthnRequest, it was a '{}'", requestContext
	                    .getInboundSAMLMessage().getClass().getName());
	            requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null,
	                    "Invalid SAML AuthnRequest message."));
	            throw new ProfileException("Invalid SAML AuthnRequest message.");
	        }
	    } catch (MessageDecodingException e) {
	        String msg = "Error decoding authentication request message";
	        requestContext.setFailureStatus(buildStatus(StatusCode.REQUEST_UNSUPPORTED_URI, StatusCode.REQUEST_DENIED_URI, msg));
	        log.warn(msg, e);
	        throw new ProfileException(msg, e);
	    } catch (SecurityException e) {
	        String msg = "Message did not meet security requirements";
	        requestContext.setFailureStatus(buildStatus(StatusCode.REQUEST_DENIED_URI, StatusCode.REQUEST_DENIED_URI, msg));
	        log.warn(msg, e);
	        throw new ProfileException(msg, e);
	    }
	    populateRequestContext(requestContext);
	}

	/**
	 * Creates an authentication request context from the current environmental information.
	 * 
	 * @param in inbound transport
	 * @param out outbount transport
	 * 
	 * @return created authentication request context
	 * 
	 * @throws ProfileException thrown if there is a problem creating the context
	 */
	protected WSFedRequestContext buildRequestContext(HTTPInTransport in,
	        HTTPOutTransport out) throws ProfileException {
		WSFedRequestContext requestContext = new WSFedRequestContext();
	
	    requestContext.setCommunicationProfileId(getProfileId());
	    requestContext.setMessageDecoder(getInboundMessageDecoder(requestContext));
	    requestContext.setInboundMessageTransport(in);
	    requestContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);
	    requestContext.setOutboundMessageTransport(out);
	    requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML20P_NS);
	    requestContext.setMetadataProvider(getMetadataProvider());
	
	    String relyingPartyId = requestContext.getInboundMessageIssuer();
	    requestContext.setPeerEntityId(relyingPartyId);
	    requestContext.setInboundMessageIssuer(relyingPartyId);
	    requestContext.setOutboundHandlerChainResolver(getOutboundHandlerChainResolver());
	
	    return requestContext;
	}

    /** {@inheritDoc} */
    protected void populateRelyingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateRelyingPartyInformation(requestContext);

        EntityDescriptor relyingPartyMetadata = requestContext.getPeerEntityMetadata();
        if (relyingPartyMetadata != null) {
            requestContext.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setPeerEntityRoleMetadata(relyingPartyMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }

    /** {@inheritDoc} */
    protected void populateAssertingPartyInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        super.populateAssertingPartyInformation(requestContext);

        EntityDescriptor localEntityDescriptor = requestContext.getLocalEntityMetadata();
        if (localEntityDescriptor != null) {
            requestContext.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            requestContext.setLocalEntityRoleMetadata(localEntityDescriptor
                    .getIDPSSODescriptor(SAMLConstants.SAML20P_NS));
        }
    }
    
    
	
	/**
     * Creates an authentication statement for the current request.
     * 
     * @param requestContext current request context
     * 
     * @return constructed authentication statement
     */
    protected AuthnStatement buildAuthnStatement(WSFedRequestContext requestContext) {

        AuthnContext authnContext = buildAuthnContext(requestContext);

        AuthnStatement statement = authnStatementBuilder.buildObject();
        statement.setAuthnContext(authnContext);
        statement.setAuthnInstant(new DateTime());

        Session session = getUserSession(requestContext.getInboundMessageTransport());
        if (session != null) {
            statement.setSessionIndex(session.getSessionID());
        }

        long maxSPSessionLifetime = requestContext.getProfileConfiguration().getMaximumSPSessionLifetime();
        if (maxSPSessionLifetime > 0) {
            DateTime lifetime = new DateTime(DateTimeZone.UTC).plus(maxSPSessionLifetime);
            log.debug("Explicitly setting SP session expiration time to '{}'", lifetime.toString());
            statement.setSessionNotOnOrAfter(lifetime);
        }

        statement.setSubjectLocality(buildSubjectLocality(requestContext));

        return statement;
    }
    
    /**
     * Creates an {@link AuthnContext} for a successful authentication request.
     * 
     * @param requestContext current request
     * 
     * @return the built authn context
     */
    protected AuthnContext buildAuthnContext(WSFedRequestContext requestContext) {
        AuthnContext authnContext = authnContextBuilder.buildObject();
        AuthnContextClassRef ref = authnContextClassRefBuilder.buildObject();
        // I suppose this could be a parameter to the profile
        ref.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        authnContext.setAuthnContextClassRef(ref);
        return authnContext;
    }

    /**
     * Constructs the subject locality for the authentication statement.
     * 
     * @param requestContext curent request context
     * 
     * @return subject locality for the authentication statement
     */
    protected SubjectLocality buildSubjectLocality(WSFedRequestContext requestContext) {
        HTTPInTransport transport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        SubjectLocality subjectLocality = subjectLocalityBuilder.buildObject();
        subjectLocality.setAddress(transport.getPeerAddress());
        return subjectLocality;
    }

    
    /**
     * Selects the appropriate endpoint for the relying party and stores it in the request context.
     * 
     * @param requestContext current request context
     * 
     * @return Endpoint selected from the information provided in the request context
     */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        AuthnRequest authnRequest = ((WSFedRequestContext) requestContext).getInboundSAMLMessage();

        Endpoint endpoint = null;
        if (requestContext.getRelyingPartyConfiguration().getRelyingPartyId() == SAMLMDRelyingPartyConfigurationManager.ANONYMOUS_RP_NAME) {
            if (authnRequest.getAssertionConsumerServiceURL() != null) {
                endpoint = endpointBuilder.buildObject();
                endpoint.setLocation(authnRequest.getAssertionConsumerServiceURL());
                if (authnRequest.getProtocolBinding() != null) {
                    endpoint.setBinding(authnRequest.getProtocolBinding());
                } else {
                    log.warn("Unable to generate endpoint for anonymous party.  No binding provided.");
                }
            } else {
                log.warn("Unable to generate endpoint for anonymous party.  No ACS url provided.");
            }
        } else {

           AuthnResponseEndpointSelector endpointSelector = new AuthnResponseEndpointSelector();
           endpointSelector.setEndpointType(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
           endpointSelector.setMetadataProvider(getMetadataProvider());
           endpointSelector.setEntityMetadata(requestContext.getPeerEntityMetadata());
           endpointSelector.setEntityRoleMetadata(requestContext.getPeerEntityRoleMetadata());
           endpointSelector.setSamlRequest(requestContext.getInboundSAMLMessage());

           // allow any of the RP's endpoints
           List<Endpoint> endpoints = endpointSelector.getEntityRoleMetadata().getEndpoints(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
           for (int i=0; i<endpoints.size(); i++) {
               log.debug("adding acceptable ep: " + endpoints.get(i).getBinding());
               endpointSelector.getSupportedIssuerBindings().add(endpoints.get(i).getBinding());
           }
           endpoint = endpointSelector.selectEndpoint();
        }

        return endpoint;
    }
    
    /**
     * Deserailizes an authentication request from a string.
     * 
     * @param request request to deserialize
     * 
     * @return the request XMLObject
     * 
     * @throws UnmarshallingException thrown if the request can no be deserialized and unmarshalled
     */
    protected AuthnRequest deserializeRequest(String request) throws UnmarshallingException {
        try {
            Element requestElem = getParserPool().parse(new StringReader(request)).getDocumentElement();
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(requestElem);
            return (AuthnRequest) unmarshaller.unmarshall(requestElem);
        } catch (Exception e) {
            throw new UnmarshallingException("Unable to read serialized authentication request");
        }
    }
    
    /**
     * Build the outbound handler chain.
     *
     * @return the handler chain
     */
    protected HandlerChain buildOutboundHandlerChain() {
        BasicHandlerChain handlerChain = new BasicHandlerChain();

        handlerChain.getHandlers().add( new Handler() {
            public void invoke(MessageContext msgContext) throws HandlerException {
                SAMLMessageContext samlMsgCtx = (SAMLMessageContext) msgContext;
                if (samlMsgCtx.getOutboundSAMLMessage() != null) {
                    try {
                        SAMLEncoderHelper.signMessage(samlMsgCtx);
                    } catch (MessageEncodingException e) {
                        throw new HandlerException("Error signing SAML message", e);
                    }
                }
            }
        });

        handlerChain.getHandlers().add( new Handler() {
            public void invoke(MessageContext msgContext) throws HandlerException {
                SAMLMessageContext samlMsgCtx = (SAMLMessageContext) msgContext;
                XMLObject bodyObj = samlMsgCtx.getOutboundSAMLMessage();
                Envelope envelope = (Envelope) msgContext.getOutboundMessage();
                envelope.getBody().getUnknownXMLObjects().add(bodyObj);
            }
        });

        AddWSFedResponseHandler wsFedHandler = new AddWSFedResponseHandler();
        wsFedHandler.setACSURLValueSource(new SAMLPeerEntityEndpointLocationExtractor());
        handlerChain.getHandlers().add(wsFedHandler);

       return handlerChain;
    }

    /** In case we ever add something to the base context **/
    protected class WSFedRequestContext extends BaseSAML2ProfileRequestContext<AuthnRequest, Response, SSOConfiguration> {
    }
    
    
    /**
     * Get the resolver used to resolve the outbound handler chain.
     *
     * @return the handler chain resolver
     */
    protected HandlerChainResolver getOutboundHandlerChainResolver() {
        return outboundHandlerChainResolver;
    }

    /** {@inheritDoc} */
    protected SAMLMessageEncoder getOutboundMessageEncoder(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        return messageEncoder;
    }
    
}
