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
package org.esco.cas.authentication.principal;

import org.esco.cas.impl.SamlAuthInfo;

import java.util.ArrayList;
import java.util.List;


/**
 * Abstract class for SAML 2.0 CAS Credentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class Saml20MultiAccountCredentials extends Saml20Credentials implements ISaml20Credentials, IMultiAccountCredential {

	/** SVUID. */
	private static final long serialVersionUID = -1876582686714487731L;

	private List<String> resolvedPrincipalIds = new ArrayList<String>();

	private String opaqueId;

	private List<String> federatedIds;

	private String userChooseId;

	public Saml20MultiAccountCredentials() {
		super();
	}

	@Override
	public String toString() {
		return "Saml20MultiAccountCredentials [resolvedPrincipalIds=" + resolvedPrincipalIds + ", opaqueId=" + opaqueId + ", federatedIds=" + federatedIds + ", SAML20Credentials=" + super.toString() + "]";
	}

	@Override
	public boolean isMultiAccountManagement() {
		return true;
	}

	public List<String> getResolvedPrincipalIds() {
		return resolvedPrincipalIds;
	}

	public void setResolvedPrincipalIds(final List<String> resolvedPrincipalIds) {
		this.resolvedPrincipalIds = resolvedPrincipalIds;
	}

	public String getOpaqueId() {
		return opaqueId;
	}

	public void setOpaqueId(final String opaqueId) {
		this.opaqueId = opaqueId;
	}

	public List<String> getFederatedIds() {
		return federatedIds;
	}

	public void setFederatedIds(final List<String> federatedIds) {
		this.federatedIds = federatedIds;
	}

	public boolean isUserChooseId() {
		return userChooseId != null;
	}

	public void setUserChooseId(final String userChooseId) {
		this.userChooseId = userChooseId;
	}

	public String getUserChooseId() {
		return userChooseId;
	}
}
