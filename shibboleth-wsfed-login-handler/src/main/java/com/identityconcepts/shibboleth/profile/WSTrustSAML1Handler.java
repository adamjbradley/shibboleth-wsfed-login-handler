/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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


import java.io.FileInputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.joda.time.DateTime;

import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Request;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML1AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.ShibbolethSAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.AttributeDefinition;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.saml1.AbstractSAML1ProfileHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml1.BaseSAML1ProfileRequestContext;


import com.identityconcepts.shibboleth.config.relyingparty.InfocardSTS1Configuration;

/** Infocard handler for STS SAML1 requests. */
public class WSTrustSAML1Handler extends AbstractSAML1ProfileHandler {

        public final static String XMLNS_SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
        public final static String XMLNS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
        public final static String XMLNS_IC = "http://schemas.xmlsoap.org/ws/2005/05/identity";
        public final static String XMLNS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        public final static String XMLNS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public final static String XMLNS_WSA = "http://www.w3.org/2005/08/addressing";
        public final static String XMLNS_WST = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        public final static String XMLNS_WSP = "http://schemas.xmlsoap.org/ws/2004/09/policy";
        public final static String XMLNS_WSID = "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity";
        public final static String SAML_ASSERTIONID = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID";
        public final static String XMLNS_DS = "http://www.w3.org/2000/09/xmldsig#";

        public final static String subjectConfMethod = "urn:oasis:names:tc:SAML:1.0:cm:bearer";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSTrustSAML1Handler.class);

    private XMLObjectBuilder<Signature> signatureBuilder;

    private HashMap<String, String> attributeMap;

    /**
     * Constructor.
     * 
     */
    public WSTrustSAML1Handler() {
        super();
        log.debug("Infocard SAML1handler constructor:");
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);

    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:infocard:sts";
    }

    protected InfocardSTSRequest request;
    public void setRequest(InfocardSTSRequest req) {
          request = req;
    }

        
    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        log.debug("Infocard SAML1 STShandler processing incomming request");
        InfocardSTS1RequestContext requestContext = completeDecodeRequest(inTransport, outTransport);
        generateAssertion(requestContext);
    }


    protected List<String> getNameFormats(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();
        nameFormats.add("urn:mace:shibboleth:1.0:nameIdentifier");
        return nameFormats;
    }

    /**
     * Decodes an incoming request and populates a created request context with the resultant information.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @return the created request context
     * 
     * @throws ProfileException throw if there is a problem decoding the request
     */

    protected InfocardSTS1RequestContext completeDecodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        log.debug(".. complete decode saml1 sts request");
 

        InfocardSTS1RequestContext requestContext = new InfocardSTS1RequestContext();
        requestContext.setPrincipalName(request.principalName);
        requestContext.setSecurityPolicyResolver(getSecurityPolicyResolver());

        requestContext.setCommunicationProfileId(InfocardSTS1Configuration.PROFILE_ID);
        requestContext.setInboundMessageTransport(inTransport);
        requestContext.setInboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        requestContext.setOutboundMessageTransport(outTransport);
        requestContext.setOutboundSAMLProtocol(SAMLConstants.SAML11P_NS);

        String relyingPartyID = request.relyingPartyID;
        // log.debug(".. saml1 rp: " + relyingPartyID);

        requestContext.setInboundMessageIssuer(relyingPartyID);

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyID);
        if (rpConfig == null) {
            log.error("Unable to retrieve relying party configuration data for entity with ID {}", relyingPartyID);
            throw new ProfileException("Unable to retrieve relying party configuration data for entity with ID "
                    + relyingPartyID);
        }
        requestContext.setRelyingPartyConfiguration(rpConfig);
        requestContext.setLocalEntityId(rpConfig.getProviderId());
    
        InfocardSTS1Configuration profileConfig = (InfocardSTS1Configuration) rpConfig
                .getProfileConfiguration(InfocardSTS1Configuration.PROFILE_ID);
        requestContext.setProfileConfiguration(profileConfig);


        // set the real relying party as the audience
        Collection<String> aud = profileConfig.getAssertionAudiences();
        aud.clear();
        String fixrp = null;
        int qpos = request.realRelyingParty.indexOf('?');
        if (qpos>1) fixrp =  request.realRelyingParty.substring(0, qpos);
        else fixrp =  request.realRelyingParty;
        log.debug("setting audience:" + fixrp);
        aud.add(fixrp);

        // makeup a generic relying party
        qpos = fixrp.indexOf("//");
        if (qpos>1) {
           qpos = fixrp.indexOf('/', qpos+3);
           if (qpos>1) {
              fixrp =  fixrp.substring(0, qpos+1);
              log.debug("setting audience:" + fixrp);
              aud.add(fixrp);
           }
        }
       

        log.debug("looking for sts1 signing cred");
        if (profileConfig.getSigningCredential() != null) {
            requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
            log.debug("signing cred from sts1 profile config");
        } else if (rpConfig.getDefaultSigningCredential() != null) {
            requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
            log.debug("signing cred from sts1 default config");
        }
        
        // add requested attributes - convert from requested uri to attribute id

        HashSet<String> attrs = new HashSet<String>();
        attrs.add("transientId");

        attributeMap = new HashMap<String, String>();   // <id, uri>

        // Look through SAML1 encoders for requested attributes

        SAML1AttributeAuthority attributeAuthority = profileConfig.getAttributeAuthority();
        Map<String, AttributeDefinition> definitions =
                     ((ShibbolethSAML1AttributeAuthority)attributeAuthority).getAttributeResolver().getAttributeDefinitions();
        for (AttributeDefinition definition : definitions.values()) {
           List<AttributeEncoder> encoders = definition.getAttributeEncoders();
           for (AttributeEncoder encoder : encoders) {
              if (encoder instanceof SAML1AttributeEncoder) {
                 SAML1AttributeEncoder enc = (SAML1AttributeEncoder)encoder;
                 String attrname = enc.getAttributeName();
                 String attrns = enc.getNamespace();
                 int nslen = attrns.length();
                 // log.debug(".... looking at " + attrname + ", namespace=" + attrns);
                 for (String ra : request.requestedAttributes) {
                   if (ra.startsWith(attrns)) {
                      // log.debug(".... namespace match");
                      if (ra.substring(nslen+1).equals(attrname)) {
                         String id = definition.getId();
                         log.debug(".... found attribute " + id + " = " + ra);
                         attrs.add(id);
                         attributeMap.put(id, ra);
                      }
                   }
                 }
              }
           }
        }
        
        requestContext.setRequestedAttributes(attrs);

        return requestContext;
    }


    protected void generateAssertion(InfocardSTS1RequestContext requestContext) throws ProfileException {

         // resolve the attributes

         InfocardSTS1Configuration profileConfig = requestContext.getProfileConfiguration();
         SAML1AttributeAuthority attributeAuthority = profileConfig.getAttributeAuthority();
         if (attributeAuthority==null) {
            log.error(".. no attribute authority");
            return;
         }
         
         try {
            log.debug("Resolving attributes for principal {} of SAML request from relying party {}",
                      requestContext.getPrincipalName(), requestContext.getInboundMessageIssuer());
            Map<String, BaseAttribute> principalAttributes =
                        ((ShibbolethSAML1AttributeAuthority)attributeAuthority).getAttributeResolver().resolveAttributes(requestContext);
            requestContext.setAttributes(principalAttributes);
            // log.debug(".. have " + principalAttributes.size() + "attributes");

            // store the string values for display

            HashMap<String, String> displayAttributes = new HashMap<String, String>();   // <uri, display value>
            for (BaseAttribute attr : principalAttributes.values())  {
                for (Object o : attr.getValues()) {
                    if (o!=null) {
                        String uri = attributeMap.get(attr.toString());
                        if (uri != null) {
                           // log.debug("... found " + attr.toString() + "in the attribute map = " + uri);
                           String ov = displayAttributes.get(uri);
                           if (ov==null) ov = "";
                           else ov = ov.concat(";");
                           displayAttributes.put(uri, ov.concat(o.toString()));
                        }
                    }
                }
            }
            request.displayAttributes = displayAttributes;
        
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error resolving attributes"));
            throw new ProfileException("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
        }

        requestContext.setReleasedAttributes(requestContext.getAttributes().keySet());

        log.debug(".. building attribute statement");

        ArrayList<Statement> statements = new ArrayList<Statement>();

        AttributeStatement attributeStatement = buildAttributeStatement(requestContext, subjectConfMethod);
        if (attributeStatement != null) {
            statements.add(attributeStatement);
        }

        DateTime issueInstant = new DateTime();
        Assertion assertion = buildAssertion(requestContext, issueInstant);
        if (statements != null && !statements.isEmpty()) {
            assertion.getStatements().addAll(statements);
        }

        log.debug(".. signing assertion");
        signAssertion(requestContext, assertion);
        request.assertion = assertion;
    }



    /** Represents the internal state of a Infocard STS request while it's being processed by the IdP. */

    protected class InfocardSTS1RequestContext extends
            BaseSAML1ProfileRequestContext<Request, Response, InfocardSTS1Configuration>  {

        /** SP-provide assertion consumer service URL. */
        private String spAssertionConsumerService;
    }


    protected void signAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        log.debug("Determining if SAML assertion to relying party {} should be signed", requestContext
                .getInboundMessageIssuer());

        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        log.debug("Determining signing credntial for assertion to relying party {}", requestContext
                .getInboundMessageIssuer());
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
            log.debug("no saml1 profile signing cred, using def cred");
        } else log.debug("using saml1 profile signing cred");
/***
        Credential signatureCredential = requestContext.getOutboundSAMLMessageSigningCredential();
 ***/

        if (signatureCredential == null) {
            throw new ProfileException("No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId()
                    + " or it's SAML2 attribute query profile configuration");
        }

        log.debug("Signing assertion to relying party {}", requestContext.getInboundMessageIssuer());
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signatureCredential);
        try {
            SecurityHelper.prepareSignatureParams(signature, signatureCredential, null, null);
        } catch (SecurityException e) {
            throw new ProfileException("Error preparing signature for signing", e);
        }

        assertion.setSignature(signature);

        Marshaller assertionMarshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        try {
            assertionMarshaller.marshall(assertion);
            Signer.signObject(signature);
        } catch (MarshallingException e) {
            log.error("Unable to marshall assertion for signing", e);
            throw new ProfileException("Unable to marshall assertion for signing", e);
        } catch (SignatureException e) {
            log.error("Unable to sign assertion ", e);
            throw new ProfileException("Unable to sign assertion", e);
        }
    }

    /* We don't have a relying party endpoint */
    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        return null;
    }
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
    }


}
