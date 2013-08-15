/*
 * Copyright [2008] [University Corporation for Advanced Internet Development, Inc.]
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

import java.io.BufferedReader;
import java.io.StringReader;
import java.io.Reader;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.security.cert.X509Certificate;
import java.security.Security;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.net.URLDecoder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
// import org.w3c.dom.Node;

import org.apache.xml.security.encryption.XMLCipher;
import org.opensaml.xml.security.SecurityHelper;
import java.security.cert.Certificate;
import java.security.Key;


// import org.opensaml.common.SAMLObject;
// import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
// import org.opensaml.saml1.core.Request;
// import org.opensaml.saml1.core.Response;
// import org.opensaml.saml1.core.Status;
// import org.opensaml.saml1.core.StatusCode;
// import org.opensaml.saml1.core.StatusCode;
// import org.opensaml.saml1.core.StatusMessage;
// import org.opensaml.saml1.core.Assertion;
// import org.opensaml.saml1.core.AttributeStatement;
// import org.opensaml.saml1.core.Attribute;
// import org.opensaml.saml1.core.impl.AssertionUnmarshaller;
// import org.opensaml.saml2.metadata.Endpoint;
// import org.opensaml.saml2.metadata.Endpoint;
// import org.opensaml.saml2.metadata.EntityDescriptor;
// import org.opensaml.saml2.metadata.SPSSODescriptor;
// import org.opensaml.saml2.metadata.provider.MetadataProvider;
// import org.opensaml.saml2.metadata.provider.MetadataProviderException;
// import org.opensaml.ws.transport.http.HTTPInTransport;
// import org.opensaml.ws.transport.http.HTTPOutTransport;
// import org.opensaml.ws.transport.http.HTTPTransportUtils;
// import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
// import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

// import org.opensaml.xml.parse.BasicParserPool;
// import org.opensaml.xml.parse.ParserPool;
// import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.credential.Credential;

// import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
// import org.opensaml.xml.util.DatatypeHelper;

// import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
// import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
// import org.opensaml.xml.security.CriteriaSet;
// import org.opensaml.xml.security.criteria.EntityIDCriteria;

// import org.opensaml.xml.security.x509.PKIXValidationInformation;
// import org.opensaml.xml.security.x509.StaticPKIXValidationInformationResolver;


// import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
// import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
// import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
// import org.opensaml.xml.security.keyinfo.provider.DSAKeyValueProvider;
// import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
// import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;



// import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;


// import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
// import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
// import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
// import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

import com.identityconcepts.shibboleth.config.relyingparty.InfocardCardConfiguration;


/** Infocard encryptedelement decrypter. */
public class ElementDecrypter {

     static {
        org.apache.xml.security.Init.init();
        Security.addProvider(new BouncyCastleProvider());
     }

    public final static String XMLNS_WSA = "http://www.w3.org/2005/08/addressing";
    public final static String XMLNS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";

    private String relyingParty;
    private Credential decryptCredential;
    private Key kek;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ElementDecrypter.class);

    /**
     * Constructor.
     * 
     */
    public ElementDecrypter(Credential cred) {
        log.debug("Infocard ElementDecrypter constructor");
        decryptCredential = cred;
        kek = SecurityHelper.extractDecryptionKey(cred);
        if (kek==null) log.warn("ElementDecrypter: no kek!");
    }

    protected boolean decrypt(Document doc, Element ele) {
 
        try {

           // XMLCipher xmlCipher = XMLCipher.getProviderInstance(XMLCipher.AES_256, "BC");
           XMLCipher xmlCipher = XMLCipher.getInstance();
           xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
           xmlCipher.setKEK(kek);
           xmlCipher.doFinal(doc, ele);

        } catch (Exception e) { 
            log.error("Decrypter encountered error", e); 
            return (false);
        }

        return (true);
    }

}
