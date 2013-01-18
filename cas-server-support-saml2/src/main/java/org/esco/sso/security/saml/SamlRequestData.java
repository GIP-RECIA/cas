/**
 * 
 */
package org.esco.sso.security.saml;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang.ArrayUtils;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlRequestData implements Serializable {

	/** SVUID. */
	private static final long serialVersionUID = -189907767972279983L;

	/** The IdP connector which build this request. */
	private transient ISaml20IdpConnector idpConnectorBuilder;

	/** Unique request ID. */
	private String id;

	/** Encoded request. */
	private String samlRequest;

	/** Relay state. */
	private String relayState;

	/** Endpoint URL for request. */
	private String endpointUrl;

	/** Initial CAS request parameters. */
	private Map<String, String[]> parametersMap;

	private transient ISamlDataAdaptor samlDataAdaptor;

	/**
	 * Default Constructor
	 * 
	 * @param idpConnector the IdP connector which build this request
	 */
	public SamlRequestData(final ISaml20IdpConnector idpConnector,
			final ISamlDataAdaptor adaptor) {
		this.idpConnectorBuilder = idpConnector;
		this.samlDataAdaptor = adaptor;
	}

	/**
	 * Build the SAML HTTP-Redirect request URL.
	 * 
	 * @return the HTTP-Redirect request URL
	 */
	public String buildSamlHttpRedirectRequestUrl() {
		String redirectUrl = null;

		if (this.samlDataAdaptor != null) {
			redirectUrl = this.samlDataAdaptor.buildHttpRedirectRequest(this);
		}

		return redirectUrl;
	}

	/**
	 * Build the SAML HTTP-POST request parameters.
	 * 
	 * @return the HTTP-POST request params
	 */
	public Collection<Entry<String, String>> buildSamlHttpPostRequestParams() {
		Collection<Entry<String, String>> params = null;

		if (this.samlDataAdaptor != null) {
			params = this.samlDataAdaptor.buildHttpPostParams(this);
		} else {
			params = new ArrayList<Entry<String, String>>();
		}

		return params;
	}

	/**
	 * Retrieve the first value of a parameter in the initial HTTP request.
	 * 
	 * @param key the parameter key
	 * @return the parameter value
	 */
	public String getParameter(final String key) {
		String parameter = null;
		String[] parameters = this.getParameters(key);

		if (!ArrayUtils.isEmpty(parameters)) {
			parameter = parameters[0];
		}

		return parameter;
	}

	/**
	 * Retrieve all values of a parameter in the initial HTTP request.
	 * @param key the parameter key
	 * @return the parameter values
	 */
	public String[] getParameters(final String key) {
		String[] parameters = null;

		if (this.parametersMap != null) {
			parameters = this.parametersMap.get(key);
		}

		return parameters;
	}

	/**
	 * Unique request ID.
	 * 
	 * @return Unique request ID
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * Unique request ID
	 * @param id Unique request ID
	 */
	public void setId(final String id) {
		this.id = id;
	}

	/**
	 * Encoded request.
	 * @return Encoded request.
	 */
	public String getSamlRequest() {
		return this.samlRequest;
	}

	/**
	 * Encoded request.
	 * @param samlRequest Encoded request.
	 */
	public void setSamlRequest(final String samlRequest) {
		this.samlRequest = samlRequest;
	}

	/**
	 * Relay state.
	 * @return Relay state.
	 */
	public String getRelayState() {
		return this.relayState;
	}

	/**
	 * Relay state.
	 * @param relayState Relay state.
	 */
	public void setRelayState(final String relayState) {
		this.relayState = relayState;
	}

	/**
	 * Initial CAS request parameters.
	 * @return Initial CAS request parameters.
	 */
	public Map<String, String[]> getParametersMap() {
		return this.parametersMap;
	}

	/**
	 * Initial CAS request parameters.
	 * @param parametersMap Initial CAS request parameters.
	 */
	public void setParametersMap(final Map<String, String[]> parametersMap) {
		this.parametersMap = new HashMap<String, String[]>(parametersMap);
	}

	/**
	 * Endpoint URL for request.
	 * @return Endpoint URL for request.
	 */
	public String getEndpointUrl() {
		return this.endpointUrl;
	}

	/**
	 * Endpoint URL for request.
	 * @param endpointUrl Endpoint URL for request.
	 */
	public void setEndpointUrl(final String endpointUrl) {
		this.endpointUrl = endpointUrl;
	}

	/**
	 * The IdP connector which build this request.
	 * @return The IdP connector which build this request
	 */
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}

}
