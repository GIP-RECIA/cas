/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.IOException;

import org.esco.sso.security.saml.util.SamlTestResourcesHelper;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.signature.Signature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Tests d'intégration de la library opensaml2 dans le SP Processor.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:idpSideConfigContext.xml")
public class OpenSaml20ProcessingTest {

	@SuppressWarnings("unused")
	@javax.annotation.Resource(name="responseAssertSigned")
	private ClassPathResource responseAssertSigned;

	@javax.annotation.Resource(name="responseSimpleSigned")
	private ClassPathResource responseSimpleSigned;

	@SuppressWarnings("unused")
	@javax.annotation.Resource(name="responseFullSigned")
	private ClassPathResource responseFullSigned;

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void signMessage() throws Exception {
		Response response = (Response) SamlTestResourcesHelper.buildOpenSamlXmlObjectFromResource(this.responseSimpleSigned);

		this.signResponse(response);
	}

	/**
	 * Temp method to sign a message.
	 * 
	 * @param samlResponse
	 * @throws IOException
	 */
	private void signResponse(final Response samlResponse) throws IOException {
		//final Assertion assertion = samlResponse.getAssertions().iterator().next();
		//Signature signature1 = this.spProcessor.buildSignature(false);
		Signature signature2 = this.spProcessor.buildSignature(false);
		//assertion.setSignature(signature1);
		samlResponse.setSignature(signature2);
		//OpenSamlHelper.httpPostEncode(assertion);
		OpenSamlHelper.httpPostEncode(samlResponse);
	}

}
