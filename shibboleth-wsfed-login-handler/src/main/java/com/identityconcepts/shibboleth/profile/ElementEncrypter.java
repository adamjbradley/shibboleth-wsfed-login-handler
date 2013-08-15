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

import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Encrypt an Element
 */

public class ElementEncrypter {

     static {
        org.apache.xml.security.Init.init();
        Security.addProvider(new BouncyCastleProvider());
     }

     private static Logger log = LoggerFactory.getLogger(ElementEncrypter.class);

        public final static String XMLNS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public final static String XMLNS_DS = "http://www.w3.org/2000/09/xmldsig#";
        public final static String XMLNS_SHA = "http://docs.oasisopen.org/wss/oasis-wss-soap-messagesecurity-1.1#ThumbprintSHA1";
        public final static String XMLNS_B64 = "http://docs.oasisopen.org/wss/2004/01/oasis200401-wss-soap-message-security-1.0#Base64Binary";
        public final static String XMLENC_ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element";
    

        private Certificate RPCert = null;

     private HostnameVerifier hostv = new HostnameVerifier() {
         public boolean verify(String urlhost, SSLSession session) {
            System.out.println("verify host: "+urlhost+" vs. "+session.getPeerHost());
            return true;
         }
     };



     // Attempt to find the relying party cert by https GET
     public void findRPCert(String urlstr) throws Exception {

        try {
          int qp;
          if ((qp=urlstr.indexOf('?'))>0) urlstr = urlstr.substring(0,qp);
          SSLContext sc = SSLContext.getInstance("TLS");
          sc.init(null, new TrustManager[] { new DummyTrustManager() }, new SecureRandom());
          HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
          URL url = new URL(urlstr);
          HttpsURLConnection.setDefaultHostnameVerifier(hostv);
          HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
          connection.connect();

          Certificate[] certs = connection.getServerCertificates();
          RPCert = certs[0];
          PublicKey pk = certs[0].getPublicKey();
          log.debug(".. GOT public key for " + urlstr);
       } catch (Exception e) {
          log.error(".. error GETting peer key: " + e);
          throw (e);
       }
     }

     public void setRPCert(Certificate certificate) {
          RPCert = certificate;
     }

	public boolean encryptElement (Element tgt) throws Exception {

           try {
		Document domDocument = tgt.getOwnerDocument();

                Element domToEncrypt = tgt;

                if (RPCert==null) {
                   log.error(".. sts element encrypter - no cert");
                   return (false);
                }

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(256);
		SecretKey secretKey = keyGenerator.generateKey();

                PublicKey publicKeyRP = RPCert.getPublicKey();
		XMLCipher keyCipher = XMLCipher.getProviderInstance(XMLCipher.RSA_OAEP, "BC");
		keyCipher.init(XMLCipher.WRAP_MODE, publicKeyRP);

		EncryptedKey encryptedKey = null;

                // create keyinfo
	        KeyInfo keyInfoKey = new KeyInfo (domDocument);
		MessageDigest mdSha1 = MessageDigest.getInstance("SHA-1");
		byte [] byteThumbPrint = mdSha1.digest(RPCert.getEncoded());
		
		Element domSTR = domDocument.createElementNS(XMLNS_WSSE, "wsse:SecurityTokenReference");
		Element domKeyIdentifier = domDocument.createElementNS (XMLNS_WSSE, "wsse:KeyIdentifier");
		domKeyIdentifier.setAttribute("ValueType", XMLNS_SHA);
		domKeyIdentifier.setAttribute("EncodingType", XMLNS_B64);
		domKeyIdentifier.appendChild(domDocument.createTextNode(org.apache.xml.security.utils.Base64.encode(byteThumbPrint)));
                log.debug("... rp thumbprint = " + org.apache.xml.security.utils.Base64.encode(byteThumbPrint));

		domSTR.appendChild(domKeyIdentifier);
	        keyInfoKey.addUnknownElement(domSTR);

                // create encrypted key
		
		encryptedKey = keyCipher.encryptKey (domDocument, secretKey);
		encryptedKey.setKeyInfo(keyInfoKey);

		EncryptionMethod encryptionMethod = encryptedKey.getEncryptionMethod();
		Element elemDigestMethod = domDocument.createElementNS (XMLNS_DS, "ds:DigestMethod");
		elemDigestMethod.setAttribute ("Algorithm", MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
		encryptionMethod.addEncryptionMethodInformation(elemDigestMethod);
		

		XMLCipher xmlCipher = XMLCipher.getProviderInstance(XMLCipher.AES_256, "BC");
	    	xmlCipher.init (XMLCipher.ENCRYPT_MODE, secretKey);

	    EncryptedData encryptedData = xmlCipher.getEncryptedData();
            encryptedData.setType(XMLENC_ELEMENT);
	    KeyInfo keyInfoEncryption = new KeyInfo (domDocument);

	   keyInfoEncryption.add (encryptedKey);
	   encryptedData.setKeyInfo (keyInfoEncryption);
           xmlCipher.doFinal(domDocument, tgt, false);
           return (true);
         
	} catch (Exception e) {
            System.out.println(".. encrypting exception: " + e );
            throw (e);
        }
    }
}
