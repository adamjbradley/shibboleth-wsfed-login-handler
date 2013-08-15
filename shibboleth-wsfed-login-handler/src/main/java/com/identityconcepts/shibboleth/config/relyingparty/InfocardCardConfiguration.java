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

package com.identityconcepts.shibboleth.config.relyingparty;

import java.util.Map;
import java.util.HashMap;
import java.util.Vector;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mchange.v2.c3p0.ComboPooledDataSource;

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;

/**
 * Infocard Card configuration settings.
 */
public class InfocardCardConfiguration extends AbstractSAMLProfileConfiguration {

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "urn:mace:shibboleth:2.0:profiles:infocard:card";

    private String cardName;
    private String cardId;
    private String cardVersion;
    private String imageGenerator;
    private String mexAddress;
    private String stsAddress;
    private String privacyNotice;
    private Map<String, InfocardClaim> supportedClaims;
    private Vector<DataSource> cardDataSources;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(InfocardCardConfiguration.class);

    /** {@inheritDoc} */
    public String getProfileId() {
        return PROFILE_ID;
    }

    /**
     * Constructor.
     *
     */
    public InfocardCardConfiguration(String name, String id, String ver, String gen, String mex, String sts, String pn ) {

        log.debug("Infocard Card constructor: id=" + id + ", ver=" + ver);
        cardName = name;
        cardId = id;
        cardVersion = ver;
        imageGenerator = gen;
        mexAddress = mex;
        stsAddress = sts;
        privacyNotice = pn;
        log.debug("loading claims");
        supportedClaims = new HashMap<String, InfocardClaim>();
        log.debug("loading sources");
        cardDataSources = new Vector<DataSource>(2);
        log.debug("InfocardCardConfiguration done");

    }

    /**
     * Gets of all the parameters
     */

    public Map<String, InfocardClaim> getSupportedClaims() {
        return supportedClaims;
    }
    public String getCardName() {
        return cardName;
    }
    public String getCardId() {
        return cardId;
    }
    public String getCardVersion() {
        return cardVersion;
    }
    public String getCardImageGenerator() {
        return imageGenerator;
    }
    public String getMexAddress() {
        return mexAddress;
    }
    public String getStsAddress() {
        return stsAddress;
    }
    public String getPrivacyNotice() {
        return privacyNotice;
    }
    public  Vector<DataSource> getCardDataSources() {
        return cardDataSources;
    }

    /**
     * Sets the list of claims supported by infocards
     */
    public void setSupportedClaims(Map<String, InfocardClaim> claims) {
        supportedClaims = claims;
    }
  
    /**
     * Sets the card data source
     */
    public void setCardDataSources(Vector<DataSource> sources) {
        cardDataSources = sources;
    }

}
