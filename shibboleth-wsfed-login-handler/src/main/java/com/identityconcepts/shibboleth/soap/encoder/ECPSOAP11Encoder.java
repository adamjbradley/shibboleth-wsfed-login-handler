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

package com.identityconcepts.shibboleth.soap.encoder;

import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.ws.soap.soap11.encoder.http.HTTPSOAP11Encoder;

/**
 * 
 */
public class ECPSOAP11Encoder extends HTTPSOAP11Encoder implements SAMLMessageEncoder {

    /** Constructor. */
    public ECPSOAP11Encoder() {}

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_SOAP11_BINDING_URI;
    }

}
