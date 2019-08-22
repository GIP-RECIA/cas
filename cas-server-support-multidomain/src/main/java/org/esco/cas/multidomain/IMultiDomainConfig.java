package org.esco.cas.multidomain;

import java.util.Set;

public abstract interface IMultiDomainConfig
{
  public abstract String getCurrentTheme();
  
  public abstract String getCurrentDomainName();
  
  public abstract String getCurrentServiceId(String paramString);
  
  public abstract Set<String> getDomains();
  
  public abstract String getOverrideIndexRedirectUrl();
}


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/multidomain/IMultiDomainConfig.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */