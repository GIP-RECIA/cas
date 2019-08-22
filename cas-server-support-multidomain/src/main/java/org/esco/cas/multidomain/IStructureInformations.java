package org.esco.cas.multidomain;

import java.util.List;
import java.util.Map;

public interface IStructureInformations {

    String getStructureName(final String uai);

    /** return the user with the current structure informations needed depending on user attribute configuration.*/
    Map<String, List<String>> applyStructureName(final Map<String, List<String>> userInfos);
}
