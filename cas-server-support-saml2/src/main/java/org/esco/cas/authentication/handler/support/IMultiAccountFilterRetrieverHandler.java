package org.esco.cas.authentication.handler.support;

import org.jasig.cas.authentication.principal.Credentials;
import org.opensaml.xml.util.Pair;

import javax.naming.directory.Attributes;
import java.util.List;

public interface IMultiAccountFilterRetrieverHandler {

    String getName();

    boolean supports(Credentials credentials);

    Pair<List<String>, List<Attributes>> retrieveAccounts(Credentials credentials);


}
