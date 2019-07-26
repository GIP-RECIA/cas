package org.esco.cas.authentication.handler.support;

import org.jasig.cas.authentication.principal.Credentials;
import org.opensaml.xml.util.Pair;

import javax.naming.directory.Attributes;
import java.util.List;
import java.util.Map;

public interface IMultiAccountFilterRetrieverHandler {

    String getName();

    boolean supports(Credentials credentials);

    Pair<List<String>, List<Map<String, List<String>>>> retrieveAccounts(Credentials credentials);


}
