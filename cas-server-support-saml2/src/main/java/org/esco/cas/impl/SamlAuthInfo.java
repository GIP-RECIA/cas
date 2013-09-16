/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package org.esco.cas.impl;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Informations about SAML 2.0 Authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlAuthInfo implements Serializable {

	/** SVUID. */
	private static final long serialVersionUID = -2408640620469852696L;

	/** Logger. */
	@SuppressWarnings("unused")
	private static final Log LOGGER = LogFactory.getLog(SamlAuthInfo.class);

	/** Entity Id of the IdP used for authentication. */
	private String idpEntityId;

	/** SAML 2.0 Subject sent by the IdP. */
	private String subjectId;

	/** IdP session index. */
	private String sessionIndex;

	public String getIdpSubject() {
		return this.subjectId;
	}

	public void setIdpSubject(final String subjectId) {
		this.subjectId = subjectId;
	}

	public String getIdpEntityId() {
		return this.idpEntityId;
	}

	public void setIdpEntityId(final String idpEntityId) {
		this.idpEntityId = idpEntityId;
	}

	public String getSessionIndex() {
		return this.sessionIndex;
	}

	public void setSessionIndex(final String sessionIndex) {
		this.sessionIndex = sessionIndex;
	}

}
