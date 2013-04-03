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
package org.esco.cas.web.flow;

import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.esco.sso.security.saml.util.SamlHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Controller to initialize the wayf.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class InitWayfAction extends AbstractAction {

	private static final Logger LOGGER = LoggerFactory.getLogger(InitWayfAction.class);

	private static final String BASE_IDP_SELECTION_GET_URL_PARAM = "baseIdpSelectGetUrl";

	@Override
	protected Event doExecute(final RequestContext context) throws Exception {
		final MutableAttributeMap viewScope = context.getViewScope();

		final String baseIdpSelectGetUrl = this.buildBaseIdpSelectionGetUrl();
		InitWayfAction.LOGGER.debug("Base IdP selection get URL: [{}].", baseIdpSelectGetUrl);
		viewScope.put(InitWayfAction.BASE_IDP_SELECTION_GET_URL_PARAM, baseIdpSelectGetUrl);

		return this.success();
	}

	/**
	 * Build the base GET URL to send from wayf to select an IdP.
	 * 
	 * @param request the HTTP request
	 * @return the base URL. (https:// [...] ? [...] &idpId=)
	 */
	@SuppressWarnings("unchecked")
	protected String buildBaseIdpSelectionGetUrl() {
		final HttpServletRequest request = ((ServletRequestAttributes)
				RequestContextHolder.currentRequestAttributes()).getRequest();

		StringBuilder sb = new StringBuilder(256);
		// Request URI
		sb.append(request.getRequestURI());
		sb.append("?");
		// Add all HTTP params
		Map<String, String[]> params = request.getParameterMap();
		for (Entry<String, String[]> paramEntry : params.entrySet()) {
			String key = paramEntry.getKey();
			String[] values = paramEntry.getValue();
			if (StringUtils.hasText(key)) {
				if (values != null) {
					for (String value : values) {
						sb.append(key);
						sb.append("=");
						sb.append(value);
						sb.append("&");
					}
				}
			}

		}

		// Add IdP selection param for the wayf
		final String idpIdParamKey = SamlHelper.getWayfConfig().getIdpIdParamKey();
		sb.append(idpIdParamKey);
		// Let the value blanked
		sb.append("=");

		String baseIdpGetRequest = sb.toString();
		return baseIdpGetRequest;
	}

}
