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

import java.util.ArrayList;
import java.util.List;

import org.esco.cas.authentication.handler.AuthenticationStatusEnum;


/**
 * Credentials supplied to achieve a multi-valued attribute authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class MultiValuedAttributeCredentials implements IResolvingCredentials, IInformingCredentials {

	/** SVUID. */
	private static final long serialVersionUID = 7737783560601653027L;
	
	/** AttributesList. */
	private List<String> attributeValues;
	
	/** The authentication status. */
	private AuthenticationStatusEnum authenticationStatus;

	/** Value from the list which permit the authentication. */
	private String authenticatedValue;

	/** The principal Id corresponding to the authenticated principal. */
	private String resolvedPrincipalId;
	
	public MultiValuedAttributeCredentials() {
		super();
		this.attributeValues = new ArrayList<String>();
	}

	@Override
	public String toString() {
		return "MultiValuedAttributeCredentials [attributeValues=" + attributeValues + ", authenticatedValue="
				+ authenticatedValue + ", resolvedPrincipalId=" + resolvedPrincipalId + "]";
	}

	/**
	 * Getter of resolvedPrincipalId.
	 *
	 * @return the resolvedPrincipalId
	 */
	@Override
	public String getResolvedPrincipalId() {
		return resolvedPrincipalId;
	}

	/**
	 * Setter of resolvedPrincipalId.
	 *
	 * @param resolvedPrincipalId the resolvedPrincipalId to set
	 */
	@Override
	public void setResolvedPrincipalId(String resolvedPrincipalId) {
		this.resolvedPrincipalId = resolvedPrincipalId;
	}

	/**
	 * Getter of authenticatedValue.
	 *
	 * @return the authenticatedValue
	 */
	public String getAuthenticatedValue() {
		return authenticatedValue;
	}

	/**
	 * Setter of authenticatedValue.
	 *
	 * @param authenticatedValue the authenticatedValue to set
	 */
	public void setAuthenticatedValue(String authenticatedValue) {
		this.authenticatedValue = authenticatedValue;
	}

	/**
	 * attributesList.
	 * 
	 * @param attributesList the attributesList to set
	 */
	public void setAttributeValues(List<String> attributesList) {
		this.attributeValues = attributesList;		
	}
	
	/**
	 * attributesList.
	 * 
	 * @return the attributesList
	 */
	public List<String> getAttributeValues() {
		return this.attributeValues;
	}

	/**
	 * The authentication status.
	 * 
	 * @return the authentication status
	 */
	public AuthenticationStatusEnum getAuthenticationStatus() {
		return this.authenticationStatus;
	}

	/**
	 * The authentication status.
	 * 
	 * @param authenticationStatus the authentication status
	 */
	public void setAuthenticationStatus(final AuthenticationStatusEnum authenticationStatus) {
		this.authenticationStatus = authenticationStatus;
	}

}
