package org.esco.cas.multidomain;

import java.util.List;
import java.util.Map;

public interface IStructureInformations {

    String getStructureName(final String uai);

    /** return the structure Name of the user current structure depending on user attribute configuration.*/
    String getStructureName(final Map<String, List<String>> userInfos);
}
