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

package com.identityconcepts.shibboleth.soap.decoder;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.ws.soap.soap11.decoder.http.HTTPSOAP11Decoder;
import org.opensaml.xml.parse.ParserPool;

/**
 * Decoder for ECP SOAP 1.1 HTTP binding.
 */
public class ECPSOAP11Decoder extends HTTPSOAP11Decoder implements SAMLMessageDecoder {

    /** Constructor.  */
    public ECPSOAP11Decoder() {
    }

    /**
     * Constructor.
     *
     * @param pool parser pool to use
     */
    public ECPSOAP11Decoder(ParserPool pool) {
        super(pool);
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_SOAP11_BINDING_URI;
    }

}
