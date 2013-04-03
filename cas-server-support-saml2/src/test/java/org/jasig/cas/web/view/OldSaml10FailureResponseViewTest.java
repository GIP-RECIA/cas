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
package org.jasig.cas.web.view;

import org.jasig.cas.authentication.principal.SamlService;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.web.view.OldSaml10FailureResponseView;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=BlockJUnit4ClassRunner.class)
public class OldSaml10FailureResponseViewTest {

	private OldSaml10FailureResponseView responseView;

	private static final String MOCK_SERVICE_ID = "https://service.De.Test.eu/truc";

	private static final String CONST_PARAM_SERVICE = "TARGET";

	private static final String ERROR_MESSAGE = "Erreur de test !";

	@Before
	public void initTest() throws ConfigurationException {
		DefaultBootstrap.bootstrap();

		this.responseView = new OldSaml10FailureResponseView();
	}

	@Test
	public void testBuildSaml10FailureResponse() throws Throwable {
		Service service = this.buildSamlService();
		String errorMessage = OldSaml10FailureResponseViewTest.ERROR_MESSAGE;

		String xmlResponse = this.responseView.buildSaml10FailureResponse(service, errorMessage);

		Assert.assertNotNull("The xml response cannot be null !", xmlResponse);

	}


	/**
	 * @return
	 */
	private SamlService buildSamlService() {
		final String body = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" MajorVersion=\"1\" MinorVersion=\"1\" RequestID=\"_192.168.16.51.1024506224022\" IssueInstant=\"2002-06-19T17:03:44.022Z\"><samlp:AssertionArtifact>artifact</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>";
		final MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContent(body.getBytes());
		request.setParameter(OldSaml10FailureResponseViewTest.CONST_PARAM_SERVICE, OldSaml10FailureResponseViewTest.MOCK_SERVICE_ID);

		final SamlService samlService = SamlService.createServiceFrom(request, null);

		return samlService;
	}

}
