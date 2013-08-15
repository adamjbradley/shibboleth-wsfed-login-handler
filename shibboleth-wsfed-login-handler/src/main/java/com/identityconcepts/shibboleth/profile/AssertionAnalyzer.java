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
import org.w3c.dom.Node;

import org.apache.xml.security.encryption.XMLCipher;
import org.opensaml.xml.security.SecurityHelper;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;

import java.math.BigInteger;


import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyImpl;

import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.impl.AssertionUnmarshaller;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.credential.Credential;

import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.util.DatatypeHelper;

import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;

import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.provider.DSAKeyValueProvider;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;



import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;


import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

import com.identityconcepts.shibboleth.config.relyingparty.InfocardCardConfiguration;


/** Infocard assertion analyzer - verify and extract ppid and key info. */
public class AssertionAnalyzer {

     static {
        org.apache.xml.security.Init.init();
        Security.addProvider(new BouncyCastleProvider());
     }

    public final static String XMLNS_WSA = "http://www.w3.org/2005/08/addressing";
    public final static String XMLNS_SAML = "urn:oasis:names:tc:SAML:1.0:assertion";

    // should be config arg?
    private String infocardRelyingParty = "urn:mace:shibboleth:2.0:infocard";
    
    private String ppid = null;
    private String pubkey = null;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AssertionAnalyzer.class);

    /**
     * Constructor.
     * 
     */
    public AssertionAnalyzer() {
        log.debug("Infocard AssertionAnalyzer constructor:");
    }

    protected boolean analyze(Element assertionElement) {
 
        try {

           AssertionUnmarshaller um = new AssertionUnmarshaller();
           Assertion signedAssertion = (Assertion) um.unmarshall(assertionElement);
           if (signedAssertion!=null) {
               log.debug("have assertion ok:");
               
               // check sig and save the pubkey
               Signature signature = signedAssertion.getSignature();
 
               KeyInfoCriteria keyInfoCriteria = new KeyInfoCriteria(signature.getKeyInfo());
               CriteriaSet keyInfoCriteriaSet = new CriteriaSet(keyInfoCriteria);
                
               KeyInfoCredentialResolver kiResolver = buildBasicInlineKeyInfoResolver();
               for (Credential kiCred : kiResolver.resolve(keyInfoCriteriaSet)) {
                 SignatureValidator validator = new SignatureValidator(kiCred);
                 try {
                     validator.validate(signature);
                     log.debug("Signature validation OK with: " + kiCred.getEntityId());
                     RSAPublicKey pk = (RSAPublicKey) kiCred.getPublicKey();
                     BigInteger mod = pk.getModulus();
                     String modString = mod.toString(16).toUpperCase();
                     log.debug(".. modulus = " + modString);
                     MessageDigest md = MessageDigest.getInstance("SHA-1");
                     md.update(modString.getBytes());
                     pubkey = Base64.encodeBytes(md.digest());
                     log.debug(".. b64 = " + pubkey);
                 } catch (ValidationException e) {
                     log.debug("Signature validation using candidate validation credential failed", e);
                     return false;
                 }
               }

               // get ppid attribute

               AttributeStatement as = signedAssertion.getAttributeStatements().get(0);
               if (as!=null) {
                  log.debug("have attribute statement");
                  List <Attribute> attrs = as.getAttributes();
                  log.debug("have " + attrs.size() + " attributes");

                  for (Attribute a: attrs) {
                     log.debug(".. chk name = " + a.getAttributeName());
                     if (a.getAttributeName().equals("privatepersonalidentifier")) {
                        XSAnyImpl value = (XSAnyImpl) a.getAttributeValues().get(0);
                        ppid = value.getTextContent();
                        log.debug(".. got ppid = " + value.getTextContent());
                     }
                  }

               }
               
           }

        } catch (Exception e) { 
            log.error("Anamyzer encountered error", e); 
            ppid = null;
        }
        return (ppid!=null);
    }


    public String getPPID() {
       return (ppid);
    }

    public String getCardKey() {
       return (pubkey);
    }

    public static Element getFirstChildElement(Node n, String ns, String localName) {
        Element e = XMLHelper.getFirstChildElement(n);
        while (e != null && !XMLHelper.isElementNamed(e, ns, localName))
            e = XMLHelper.getNextSiblingElement(e);
        return e;
    }


    protected static KeyInfoCredentialResolver buildBasicInlineKeyInfoResolver() {
        List<KeyInfoProvider> providers = new ArrayList<KeyInfoProvider>();
        providers.add( new RSAKeyValueProvider() );
        providers.add( new DSAKeyValueProvider() );
        providers.add( new InlineX509DataProvider() );
        return new BasicProviderKeyInfoCredentialResolver(providers);
    }

}
