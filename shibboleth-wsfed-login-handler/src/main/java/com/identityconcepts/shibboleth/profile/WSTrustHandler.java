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

import java.io.FileInputStream;
import java.io.FileInputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.ArrayList;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Date;
import java.util.TimeZone;


import javax.xml.namespace.QName;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.encryption.XMLCipher;


import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;

import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.XMLConstants;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;


import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

import com.identityconcepts.shibboleth.authn.InfocardSTSLoginHandler;
import com.identityconcepts.shibboleth.config.relyingparty.InfocardCardConfiguration;
import com.identityconcepts.shibboleth.config.relyingparty.InfocardClaim;

/** WSTrust handler for STS requests. */
public class WSTrustHandler extends AbstractSAMLProfileHandler {

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
        public final static String XMLNS_XENC = "http://www.w3.org/2001/04/xmlenc#";

        public final static String subjectConfMethod = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";
        public final static String XMLNS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";

    // should be config arg?
    private String relyingParty = null;
    private boolean saml1Request = true;
    private X509Certificate realRPCert = null;
    private String messageID = null;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(WSTrustHandler.class);

    /** Builder for Status objects. */
    private SAMLObjectBuilder<Status> statusBuilder;

    /** Builder for StatusCode objects. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;

    /** Builder for StatusMessage objects. */
    private SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

    /** Easy way to send an error (soap 1.1) **/
    private static String authnErrorResponse =
"<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
" <env:Body>" +
" <env:Fault>" +
" <faultcode>env:Client</faultcode>" +
" <faultstring>MESSAGE</faultstring>" +
" <detail/>" +
" </env:Fault>" +
" </env:Body>" +
"</env:Envelope>";

    /** Easy way to send an error (soap 2) **/
    private static String authnErrorResponse_2 = 
"<env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\"" +
" xmlns:rpc=\"http://www.w3.org/2003/05/soap-rpc\">" +
" <env:Body>" +
" <env:Fault>" +
" <env:Code>" +
" <env:Value>env:Sender</env:Value>" +
" <env:Subcode>" +
" <env:Value>rpc:FailedAuthentication</env:Value>" +
" </env:Subcode>" +
" </env:Code>" +
" <env:Reason>" +
" <env:Text xml:lang=\"en\">MESSAGE</env:Text>" +
" </env:Reason>" +
" </env:Fault>" +
" </env:Body>" +
"</env:Envelope>";

    /**
     * Constructor.
     * 
     */
    public WSTrustHandler(String rp) {
        super();

        log.debug("Infocard STShandler constructor:");

        relyingParty = rp;

        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(
                StatusMessage.DEFAULT_ELEMENT_NAME);

    }

    /** {@inheritDoc} */
    public String getProfileId() {
        return "urn:mace:shibboleth:2.0:idp:profiles:infocard:sts";
    }

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        log.debug("Infocard STShandler processing incomming request");
        WSTrustRequest request = decodeRequest(inTransport, outTransport);
        
        if (request!=null) {
        	
           //PRP or WSTrust
        	
        	/*
           // saml1 or saml2? 
           if (saml1Request) {
              WSTrustSAML1Handler handler = new WSTrustSAML1Handler();
              handler.setRequest(request);
              handler.setRelyingPartyConfigurationManager(getRelyingPartyConfigurationManager());
              handler.setIdGenerator(getIdGenerator());
              handler.processRequest(inTransport, outTransport);
           } else {
              InfocardSAML2Handler handler = new InfocardSAML2Handler();
              handler.setRequest(request);
              handler.setRelyingPartyConfigurationManager(getRelyingPartyConfigurationManager());
              handler.setIdGenerator(getIdGenerator());
              handler.processRequest(inTransport, outTransport);
           }
           completeSTSRequest(request, inTransport, outTransport);
        } else {
           // already sent by decoder
           // sendCannedError(inTransport, outTransport, "generic error");
            
            */
        }
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

    protected WSTrustRequest decodeRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        WSTrustRequest request = new WSTrustRequest();
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        BaseSAMLProfileRequestContext requestContext = buildRequestContext(inTransport, outTransport);

        String username = null;
        String password = null;

        Element envelope = null;
        ParserPool pp = new BasicParserPool();
        Document messageDoc = null;

        try {
            messageDoc = pp.parse(inTransport.getIncomingStream());
            envelope = messageDoc.getDocumentElement();

           log.debug(" .. message is:\n{}", XMLHelper.nodeToString(envelope));

        } catch (XMLParserException e) { 
            log.error("Encountered error parsing message into its DOM representation", e); 
            throw new ProfileException("Encountered error parsing message into its DOM representation", e);
        }

        // The header has name and password

        // log.debug("envelop is:" + envelope.getTagName());

        Element child = XMLHelper.getFirstChildElement(envelope);

        child  = getFirstChildElement(envelope, XMLNS_SOAP12, "Header");
        if (child==null) child = getFirstChildElement(envelope, XMLNS_SOAP11, "Header");
        if (child==null) {
               log.error("no header in sts request!");
               sendCannedError(inTransport, outTransport, "No request header");
               return (null);
        }

        Element cmid = getFirstChildElement(child, XMLNS_WSA, "MessageID");

        if (cmid!=null) {

           messageID = cmid.getTextContent();
           log.debug("have message id: " + messageID);
        }

        Element csec = getFirstChildElement(child, XMLNS_WSSE, "Security");

        if (csec!=null) {

           // log.debug("Security child is:" + csec.getTagName());
           
           // decrypt any encrypted block
           Element ecd = getFirstChildElement(csec, XMLNS_XENC, "EncryptedData");
           if (ecd!=null) {
              log.debug(".. decrypting an encryptedblaoc in Security header");
              ElementDecrypter dec = new ElementDecrypter(getDecryptionCredential());
              dec.decrypt(messageDoc, ecd);
           }

           log.debug(" .. after decrypt:\n{}", XMLHelper.nodeToString(csec));
             
           Element une = getFirstChildElement(csec, XMLNS_WSSE, "UsernameToken");
           if (une!=null) {
              // userid and password login
              for (Node val = une.getFirstChild(); val!=null; val=val.getNextSibling()) {
                  if (val.getNodeType()==Node.ELEMENT_NODE && val.getLocalName().equals("Username")) username = val.getTextContent();
                  if (val.getNodeType()==Node.ELEMENT_NODE && val.getLocalName().equals("Password")) password = val.getTextContent();
              }

              log.debug(" username: " + username);

              if (username.equalsIgnoreCase("joeuser"))  log.debug(" password: " + password);

              InfocardSTSLoginHandler lh = new InfocardSTSLoginHandler();
              boolean validUser = lh.authenticate(username, password);
              if (validUser) log.debug(" .. password OK!");
              else {
                  log.debug(" .. password fails!");
                  sendCannedError(inTransport, outTransport, "Invalid user/password");
                  return null;
              }
              request.principalName = username;

           }       
        }
          

        // Get the request

        Element body = getFirstChildElement(envelope, XMLNS_SOAP12, "Body");
        if (body==null) body = getFirstChildElement(envelope, XMLNS_SOAP11, "Body");
        if (body==null) {
             log.error(" .. no body of sts request!");
             sendCannedError(inTransport, outTransport, "No request body");
             return (null);
        }

        Element rst = getFirstChildElement(body, XMLNS_WST, "RequestSecurityToken");

        String clientPseudonym = null;
        String endpointReference = null;
  
        realRPCert = null;

        if (rst!=null) {

/**  some debug out if needed
            log.debug("Have RequestSecurityToken!");
            for (Element e = XMLHelper.getFirstChildElement(rst); e!=null; e = XMLHelper.getNextSiblingElement(e)) {
               log.debug(".. element: " + e.getNodeName() + ", data: " + e.getTextContent());
            }
 **/

            Element tte = getFirstChildElement(rst, XMLNS_WST, "TokenType");
            if (tte!=null) {
                String tt = tte.getTextContent();
                log.debug(" have tokentype: " + tt);
                if (tt.equals(SAMLConstants.SAML1_NS)) saml1Request = true;
                else if (tt.equals(SAMLConstants.SAML20_NS)) saml1Request = false;
            }
            if (!saml1Request) log.debug(" .. is SAML2 request");

            Element appto = getFirstChildElement(rst, XMLNS_WSP, "AppliesTo");
            if (appto!=null) {

                for (Element e = XMLHelper.getFirstChildElement(appto); e!=null; e = XMLHelper.getNextSiblingElement(e)) {

                    if (e.getLocalName().equals("EndpointReference")) {

/*** some debug out if needed
            for (Element z = XMLHelper.getFirstChildElement(e); z!=null; z = XMLHelper.getNextSiblingElement(z)) {
               log.debug(".. epr element: " + z.getNodeName() + ", data: " + z.getTextContent());
            }
 ***/

                        String epr = e.getTextContent();
                        endpointReference = epr.substring(0,epr.indexOf("/", 10)+1);

                       /** See if we can get a certificate directly from the request  */

                        Element addr = getFirstChildElement(e, XMLNS_WSA, "Address");
                        if (addr!=null) {
                            endpointReference = addr.getTextContent();
                        }
                        Element ident = getFirstChildElement(e, XMLNS_WSID, "Identity");
                        if (ident!=null) {
                            log.debug(" .. have ident!");
                            try {
                               org.apache.xml.security.keys.KeyInfo keyInfo =
                                    new org.apache.xml.security.keys.KeyInfo(getFirstChildElement(ident, XMLNS_DS, "KeyInfo"), null);
                               if (keyInfo!=null) {
                                  realRPCert = keyInfo.getX509Certificate();
                                  log.debug(" .. keyinfo, cert dn: " + realRPCert.getIssuerDN().toString());
                             
                               }
                            } catch (Exception kie) {
                                 log.error("Key exception: " + kie);
                            }
                        }
  
                    }
                 } // for
             }
        }

        request.realRelyingParty = endpointReference;
        request.relyingPartyID = relyingParty;

        // Get requested claims

        HashSet<String> requestedAttributes = new HashSet<String>();

        if (rst!=null) {

           Element claims = getFirstChildElement(rst, XMLNS_WST, "Claims");
           if (claims!=null) {

              for (Element e = getFirstChildElement(claims, XMLNS_IC, "ClaimType"); e!=null; e = XMLHelper.getNextSiblingElement(e)) {
                  log.debug(" .. claim: " + e.getAttribute("Uri"));
                  requestedAttributes.add(e.getAttribute("Uri"));
              }
           }
           log.debug(" .. total claims = " + requestedAttributes.size());

        } else {
                log.info("Error in claims, no attributes requested.");
        }
        request.requestedAttributes = requestedAttributes;

        return request;
    }



    protected Element buildResponse (InfocardSTSRequest request) throws ProfileException {

        ParserPool pp = new BasicParserPool();
        try {

            // Document doc = pp.newDocument();
            Document doc = request.assertion.getDOM().getOwnerDocument();

            // Build the SOAP envelope and body for the response.
            Element env = doc.createElementNS(XMLNS_SOAP12, "soap:Envelope");
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:soap", XMLNS_SOAP12);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:ic", XMLNS_IC);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsa", XMLNS_WSA);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wst", XMLNS_WST);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsse", XMLNS_WSSE);
            env.setAttributeNS(XMLConstants.XMLNS_NS,"xmlns:wsu", XMLNS_WSU);

            if (doc.getDocumentElement()==null)
                doc.appendChild(env);
            else
                doc.replaceChild(env, doc.getDocumentElement());


            /* build header */
            Element hdr = doc.createElementNS(XMLNS_SOAP12, "soap:Header");
            Element sec = doc.createElementNS(XMLNS_WSSE, "wsse:Security");
            sec.setAttribute("soap:mustUnderstand", "1");
            Element ts = doc.createElementNS(XMLNS_WSU, "wsu:Timestamp");
            ts.setAttribute("wsu:Id", "_6");
            // add the create time
            Element ct = doc.createElementNS(XMLNS_WSU, "wsu:Created");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
            // Calendar cal = Calendar.getInstance();
            // Date now = cal.getTime();
            Date now = new Date();
            ct.appendChild(doc.createTextNode(sdf.format(now)));
           log.debug(" .. created: " + sdf.format(now));
            ts.appendChild(ct);
            Element et = doc.createElementNS(XMLNS_WSU, "wsu:Expires");

            now.setTime(now.getTime()+10*60*1000);  // plus 10 min
            et.appendChild(doc.createTextNode(sdf.format(now)));
           log.debug(" .. expires: " + sdf.format(now));
            ts.appendChild(et);
            sec.appendChild(ts);
            hdr.appendChild(sec);

            env.appendChild(hdr);


            Element body = doc.createElementNS(XMLNS_SOAP12, "soap:Body");
            Element rstr = doc.createElementNS(XMLNS_WST, "wst:RequestSecurityTokenResponse");
            rstr.setAttribute("Context", "ProcessRequestSecurityToken");

            Element tt = doc.createElementNS(XMLNS_WST, "wst:TokenType");
            tt.appendChild(doc.createTextNode(saml1Request? SAMLConstants.SAML1_NS: SAMLConstants.SAML20_NS));
            rstr.appendChild(tt);

            Element rt = doc.createElementNS(XMLNS_WST, "wst:RequestType");
            rt.appendChild(doc.createTextNode("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"));
            rstr.appendChild(rt);

            Element rst = doc.createElementNS(XMLNS_WST, "wst:RequestedSecurityToken");

            rst.appendChild(request.assertion.getDOM());

            log.debug("pre-encrypted assertion: " + XMLHelper.nodeToString(XMLHelper.getFirstChildElement(rst)));

            // Check for need to encrypt assertion

            if (request.realRelyingParty != null) {
               Element toe = XMLHelper.getFirstChildElement(rst);
               if (toe!=null) {
                  log.debug(" .. encrypting response");
                  ElementEncrypter ee = new ElementEncrypter();
                  if (realRPCert!=null) {
                      log.debug(".. using cert from request identity for " + request.realRelyingParty);
                      ee.setRPCert((Certificate)realRPCert);
                  } else {
                     Certificate crt = getEncryptionCertificate(request.realRelyingParty);
                     if (crt!=null) {
                        log.debug(".. using cert from metadata for " + request.realRelyingParty);
                        ee.setRPCert(crt);
                     } else {
                        log.debug(".. need to find cert for " + request.realRelyingParty);
                        ee.findRPCert(request.realRelyingParty);
                     }
                  }
                  ee.encryptElement(toe);
               } else {
                  log.error(" .. could not find Assertion");
               }
            }

            rstr.appendChild(rst);

        // add the attach references

            Element rar = doc.createElementNS(XMLNS_WST, "wst:RequestedAttachedReference");
            Element str = doc.createElementNS(XMLNS_WSSE, "wsse:SecurityTokenReference");
            Element kid = doc.createElementNS(XMLNS_WSSE, "wsse:KeyIdentifier");
            kid.setAttribute("ValueType", SAML_ASSERTIONID);
            kid.appendChild(doc.createTextNode("uuid:362397b6-e5f3-4764-b50b-1bb92812ce80"));

            str.appendChild(kid);
            rar.appendChild(str);
            rstr.appendChild(rar);

        // add the unattach references

            rar = doc.createElementNS(XMLNS_WST, "wst:RequestedUnattachedReference");
            str = doc.createElementNS(XMLNS_WSSE, "wsse:SecurityTokenReference");
            kid = doc.createElementNS(XMLNS_WSSE, "wsse:KeyIdentifier");
            kid.setAttribute("ValueType", SAML_ASSERTIONID);
            kid.appendChild(doc.createTextNode("uuid:362397b6-e5f3-4764-b50b-1bb92812ce80"));

            str.appendChild(kid);
            rar.appendChild(str);
            rstr.appendChild(rar);

        // add the display values

            Element rdt = doc.createElementNS(XMLNS_IC, "ic:RequestedDisplayToken");
            Element dt = doc.createElementNS(XMLNS_IC, "ic:DisplayToken");
            dt.setAttribute("xml:lang", "en-us");


            RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(request.relyingPartyID);
            InfocardCardConfiguration cardProfileConfig = (InfocardCardConfiguration) rpConfig
                .getProfileConfiguration(InfocardCardConfiguration.PROFILE_ID);

            Map<String, InfocardClaim> cardClaims = cardProfileConfig.getSupportedClaims();

            for (Map.Entry<String, String> a : request.displayAttributes.entrySet()) {
               InfocardClaim c = cardClaims.get(a.getKey());
               if (c!=null) {
                   log.debug(".. have display value for " + a.getKey() + ", " + c.displayName + " = " + a.getValue());
                   Element dc = doc.createElementNS(XMLNS_IC, "ic:DisplayClaim");
                   dc.setAttribute("Uri", a.getKey());
                   Element dtag = doc.createElementNS(XMLNS_IC, "ic:DisplayTag");
                   dtag.appendChild(doc.createTextNode(c.displayName));
                   Element dval = doc.createElementNS(XMLNS_IC, "ic:DisplayValue");
                   dval.appendChild(doc.createTextNode(a.getValue()));
                   dc.appendChild(dtag);
                   dc.appendChild(dval);
                   dt.appendChild(dc);
               }
            }

            rdt.appendChild(dt);
            rstr.appendChild(rdt);

            body.appendChild(rstr);
            env.appendChild(body);
            return (env);

          } catch (Exception e) {
              throw new ProfileException("sendResponse error:" +  e);
          }
       }



    /**
     * Finishes a response to the Infocard STS request.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created 
     */
    protected void completeSTSRequest(InfocardSTSRequest request, HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

            log.debug(".. completeSTSRequest");

       Element response = buildResponse(request);

       try {
            // HTTPTransportUtils.setContentType(outTransport, "application/soap+xml; charset=UTF-8");
            HTTPTransportUtils.addNoCacheHeaders(outTransport);
            HTTPTransportUtils.setUTF8Encoding(outTransport);
            HTTPTransportUtils.setContentType(outTransport, "application/soap+xml");
            Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
            XMLHelper.writeNode(response, out);
            out.flush();
       } catch (Exception e) {
            log.error("sts write response: " +  e);
       }
         
       log.info("STS reply completed.");

    }


    /**
     * Sends error response to the Infocard STS request.
     * 
     * @param inTransport inbound message transport
     * @param outTransport outbound message transport
     * 
     * @throws ProfileException thrown if the response can not be created 
     */
    protected void sendCannedError(HTTPInTransport inTransport, HTTPOutTransport outTransport, String errmsg)
            throws ProfileException {
       try {
            // HTTPTransportUtils.setContentType(outTransport, "application/soap+xml; charset=UTF-8");
            HTTPTransportUtils.addNoCacheHeaders(outTransport);
            HTTPTransportUtils.setUTF8Encoding(outTransport);
            HTTPTransportUtils.setContentType(outTransport, "application/soap+xml");
            Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
            out.write(authnErrorResponse.replaceAll("MESSAGE", errmsg));
            out.flush();
       } catch (Exception e) {
            log.error("sts write response: " +  e);
       }
         
       log.info("STS reply completed.");

    }

    /**
     * Creates an authentication request context from the current environmental information.
     *
     * @param loginContext current login context
     * @param in inbound transport
     * @param out outbount transport
     *
     * @return created authentication request context
     *
     * @throws ProfileException thrown if there is a problem creating the context
     */

    protected BaseSAMLProfileRequestContext buildRequestContext(
            HTTPInTransport in, HTTPOutTransport out) throws ProfileException {
        BaseSAMLProfileRequestContext requestContext = new BaseSAMLProfileRequestContext();

        requestContext.setUserSession(getUserSession(in));
        requestContext.setInboundMessageTransport(in);
        requestContext.setOutboundMessageTransport(out);

        String relyingPartyId = relyingParty;

        RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingPartyId);
        if (rpConfig == null) {
            log.error("Unable to retrieve relying party configuration data for entity with ID {}", relyingPartyId);
            throw new ProfileException("Unable to retrieve relying party configuration data for entity with ID "
                    + relyingPartyId);
        }
        requestContext.setRelyingPartyConfiguration(rpConfig);

        InfocardCardConfiguration profileConfig = (InfocardCardConfiguration) rpConfig
                .getProfileConfiguration(InfocardCardConfiguration.PROFILE_ID);
        requestContext.setProfileConfiguration(profileConfig);

        if (profileConfig.getSigningCredential() != null) {
            requestContext.setOutboundSAMLMessageSigningCredential(profileConfig.getSigningCredential());
            log.debug("signing cred from profile config");
        } else if (rpConfig.getDefaultSigningCredential() != null) {
            requestContext.setOutboundSAMLMessageSigningCredential(rpConfig.getDefaultSigningCredential());
            log.debug("signing cred from default config");
        }

        String assertingPartyId = rpConfig.getProviderId();
        requestContext.setLocalEntityId(assertingPartyId);
        requestContext.setOutboundMessageIssuer(assertingPartyId);
        return requestContext;
    }


    /**
     * Build a status message, with an optional second-level failure message.
     *
     * @param topLevelCode top-level status code
     * @param secondLevelCode second-level status code
     * @param failureMessage An optional second-level failure message
     *
     * @return a Status object.
     */
    protected Status buildStatus(QName topLevelCode, QName secondLevelCode, String failureMessage) {
        Status status = statusBuilder.buildObject();

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(topLevelCode);
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(secondLevelCode);
            statusCode.setStatusCode(secondLevelStatusCode);
        }

        if (failureMessage != null) {
            StatusMessage msg = statusMessageBuilder.buildObject();
            msg.setMessage(failureMessage);
            status.setStatusMessage(msg);
        }

        return status;
    }

    /* DOM helper */

    public static Element getFirstChildElement(Node n, String ns, String localName) {
        Element e = XMLHelper.getFirstChildElement(n);
        while (e != null && !XMLHelper.isElementNamed(e, ns, localName))
            e = XMLHelper.getNextSiblingElement(e);
        return e;
    }

    /* Necessary methods that we don't use */

    protected Endpoint selectEndpoint(BaseSAMLProfileRequestContext requestContext) {
        return null;
    }
    protected void populateUserInformation(BaseSAMLProfileRequestContext requestContext) {
    }
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
    }


    /* Certificate helper. Gets RP cert from metadata if possible.  */

    private Certificate getEncryptionCertificate(String realRelyingParty)
    {
        try {
            MetadataProvider metadataProvider = getMetadataProvider();
            EntityDescriptor entityDescriptor = metadataProvider.getEntityDescriptor(realRelyingParty);
            if (entityDescriptor != null) {
                SPSSODescriptor spDescriptor = null;
                if (saml1Request) spDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML11P_NS);
                else spDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
                if (spDescriptor != null) {
                    List<KeyDescriptor> keyDescriptors = spDescriptor.getKeyDescriptors();
                    KeyDescriptor keyDescriptor = keyDescriptors.get(0);
                    KeyInfo keyInfo = keyDescriptor.getKeyInfo();
                    List<X509Certificate> x509Cert  = KeyInfoHelper.getCertificates(keyInfo);
                    return ((Certificate)(x509Cert.get(0)));
                }
            }
        } catch (MetadataProviderException e) {
            log.error("Unable to locate metadata for relying party: " + e);
        } catch (CertificateException e) {
            log.error("Unable to get cert from keyinfo for relying party: " + e);
        } catch (Exception e) {
            log.error("Unable to get cert from metadata for relying party: " + e);
        }
        return (null);
    }
   

    /* Element decrypter.  Assuming our default signing cert is the encryption cert */

    private Credential getDecryptionCredential() {
       Credential cred = null;
       RelyingPartyConfiguration rpConfig = getRelyingPartyConfiguration(relyingParty);
       InfocardCardConfiguration profileConfig = (InfocardCardConfiguration) rpConfig
                .getProfileConfiguration(InfocardCardConfiguration.PROFILE_ID);

/***
       if (profileConfig.getSigningCredential() != null) {
            cred = (X509Credential) profileConfig.getSigningCredential();
            log.debug("signing cred from profile config");
        } else ***/ 
        if (rpConfig.getDefaultSigningCredential() != null) {
            cred = (X509Credential) rpConfig.getDefaultSigningCredential();
            log.debug("decrypt cred from default config");
        }

        if (cred==null) log.warn(".. decrypt: no credential");
       return (cred);
   }

}
