/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.IOException;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:openSaml20IdpConnectorContext.xml")
public class OpenSaml20BuildAuthnRequestTest {

	private static final String RESOURCE_BASE_PATH = "test";

	@Resource(name="saml20AuthnRequest")
	private ClassPathResource saml20AuthnRequest;

	@Resource(name="saml20Response")
	private ClassPathResource saml20Response;

	@Resource(name="saml20Assertion")
	private ClassPathResource saml20Assertion;

	@Autowired
	private OpenSaml20IdpConnector samlProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void testBuildSaml20AuthnRequest() {
		AuthnRequest deflatedRequest = this.samlProcessor.buildAuthnRequest(SamlBindingEnum.SAML_20_HTTP_POST);


	}

	private String readFile(final org.springframework.core.io.Resource resourceFile) throws IOException {
		return FileUtils.readFileToString(resourceFile.getFile());
	}

	private MockHttpServletRequest BuildSamlMockRequest(final String responseReq) {
		MockHttpServletRequest request = new MockHttpServletRequest(new MockServletContext(OpenSaml20BuildAuthnRequestTest.RESOURCE_BASE_PATH));
		request.setMethod("POST");
		request.setParameter("SAMLRequest", Base64.encodeBytes(responseReq.getBytes()));
		return request;
	}


}
