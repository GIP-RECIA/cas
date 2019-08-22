package org.esco.cas.authentication.principal;

import java.util.List;

public interface IMultiAccountCredential {

    List<String> getResolvedPrincipalIds();

    void setResolvedPrincipalIds(final List<String> resolvedPrincipalIds);

    String getOpaqueId();

    void setOpaqueId(final String opaqueId);

    List<String> getFederatedIds();

    void setFederatedIds(final List<String> federatedIds);

    boolean isUserChooseId();

    void setUserChooseId(final String userChooseId);
}
