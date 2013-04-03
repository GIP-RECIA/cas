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
package org.esco.sso.security.saml.query.impl;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;

/**
 * SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QuerySloRequest extends SamlQuery implements IRequestWaitingForResponse {

	/** Svuid. */
	private static final long serialVersionUID = 1081464086973460157L;

	final ISaml20IdpConnector idpConnectorBuilder;

	public QuerySloRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder) {
		super(id);
		this.idpConnectorBuilder = idpConnectorBuilder;
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}


}
