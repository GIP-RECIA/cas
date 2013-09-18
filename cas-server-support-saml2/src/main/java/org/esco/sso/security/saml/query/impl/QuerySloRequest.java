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

import java.io.IOException;

import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;
import org.esco.sso.security.saml.util.SamlHelper;

/**
 * SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QuerySloRequest extends SamlQuery implements IRequestWaitingForResponse {

	/** Svuid. */
	private static final long serialVersionUID = 1081464086973460157L;

	/** IdPConnector Id wich we can serialize. */
	private String idpConnectorConfigId;
	
	private transient ISaml20IdpConnector idpConnectorBuilder;

	public QuerySloRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder) {
		super(id);
		this.idpConnectorBuilder = idpConnectorBuilder;
		this.idpConnectorConfigId = idpConnectorBuilder.getIdpConfig().getId();
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}

	private void readObject(java.io.ObjectInputStream  input) throws IOException, ClassNotFoundException {
		this.idpConnectorConfigId = (String) input.readObject();
		this.loadIdpConnector(this.idpConnectorConfigId);
	}

	private void writeObject(java.io.ObjectOutputStream output) throws IOException {
		output.writeObject(this.idpConnectorConfigId);
	}
	
	protected void loadIdpConnector(final String idpConnectorId) {
		final IIdpConfig idpConfig = SamlHelper.getWayfConfig().findIdpConfigById(idpConnectorId);
		if (idpConfig != null) {
			this.idpConnectorBuilder = idpConfig.getSaml20IdpConnector();
		}
	}


}
