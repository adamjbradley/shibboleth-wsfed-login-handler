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

package com.identityconcepts.shibboleth.saml.encoder;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper for encoding SAML protocol messages.
 */
public final class SAMLEncoderHelper {
    
    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(SAMLEncoderHelper.class);
    
    /** Constructor.*/
    private SAMLEncoderHelper() {}
    
    /**
     * Signs the given SAML message if it is a {@link SignableSAMLObject} and this encoder has signing credentials.
     * 
     * @param messageContext current message context
     * 
     * @throws MessageEncodingException thrown if there is a problem marshalling or signing the outbound message
     */
    @SuppressWarnings("unchecked")
    public static void signMessage(SAMLMessageContext messageContext) throws MessageEncodingException {
        SAMLObject outboundSAML = messageContext.getOutboundSAMLMessage();
        Credential signingCredential = messageContext.getOuboundSAMLMessageSigningCredential();

        if (outboundSAML instanceof SignableSAMLObject && signingCredential != null) {
            SignableSAMLObject signableMessage = (SignableSAMLObject) outboundSAML;

            XMLObjectBuilder<Signature> signatureBuilder = Configuration.getBuilderFactory().getBuilder(
                    Signature.DEFAULT_ELEMENT_NAME);
            Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
            
            signature.setSigningCredential(signingCredential);
            try {
                //TODO pull SecurityConfiguration from SAMLMessageContext?  needs to be added
                //TODO pull binding-specific keyInfoGenName from somewhere
                SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
            } catch (SecurityException e) {
                throw new MessageEncodingException("Error preparing signature for signing", e);
            }
            
            signableMessage.setSignature(signature);

            try {
                Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(signableMessage);
                if (marshaller == null) {
                    throw new MessageEncodingException("No marshaller registered for "
                            + signableMessage.getElementQName() + ", unable to marshall in preperation for signing");
                }
                marshaller.marshall(signableMessage);

                Signer.signObject(signature);
            } catch (MarshallingException e) {
                LOG.error("Unable to marshall protocol message in preparation for signing", e);
                throw new MessageEncodingException("Unable to marshall protocol message in preparation for signing", e);
            } catch (SignatureException e) {
                LOG.error("Unable to sign protocol message", e);
                throw new MessageEncodingException("Unable to sign protocol message", e);
            }
        }
    }

}
