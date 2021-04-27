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

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.HashMap;
import java.util.Map;

import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;
import org.esco.sso.security.saml.util.SamlHelper;
import org.springframework.util.Assert;

/**
 * SAML Authn Request.
 *
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QueryAuthnRequest extends SamlQuery implements IRequestWaitingForResponse, Externalizable {

	/** Svuid. */
	private static final long serialVersionUID = 2263117124596805999L;

	/** Initial CAS request parameters. */
	private Map<String, String[]> parametersMap;

	/** IdPConnector Id wich we can serialize. */
	private String idpConnectorId;

	/** IdpConnector which build this request. */
	private transient ISaml20IdpConnector idpConnectorBuilder;

	public QueryAuthnRequest() {
		super();
	}

	public QueryAuthnRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder,
			final Map<String, String[]> parametersMap) {
		super(id);
		Assert.notNull(idpConnectorBuilder, "No IdP Connector builder provided !");
		Assert.notNull(parametersMap, "No parameters map provided !");

		this.parametersMap = new HashMap<String, String[]>(parametersMap);
		this.idpConnectorBuilder = idpConnectorBuilder;
		this.idpConnectorId = idpConnectorBuilder.getIdpConfig().getId();
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}

	public Map<String, String[]> getParametersMap() {
		return this.parametersMap;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void readExternal(ObjectInput input) throws IOException, ClassNotFoundException {
		this.parametersMap = (Map<String, String[]>) input.readObject();
		this.idpConnectorId = (String) input.readObject();
		this.loadIdpConnector(this.idpConnectorId);
	}

	@Override
	public void writeExternal(ObjectOutput output) throws IOException {
		output.writeObject(this.parametersMap);
		output.writeObject(this.idpConnectorId);
	}

	protected void loadIdpConnector(final String idpConnectorId) {
		final IIdpConfig idpConfig = SamlHelper.getWayfConfig().findIdpConfigById(idpConnectorId);
		if (idpConfig != null) {
			this.idpConnectorBuilder = idpConfig.getSaml20IdpConnector();
		}
	}

}