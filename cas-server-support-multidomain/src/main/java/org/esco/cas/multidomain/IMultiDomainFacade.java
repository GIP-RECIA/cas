package org.esco.cas.multidomain;

import org.esco.cas.authentication.principal.MultiDomainWebApplicationService;
import org.jasig.cas.authentication.principal.WebApplicationService;

public abstract interface IMultiDomainFacade
{
  public abstract MultiDomainWebApplicationService buildMultiDomainWebAppService(WebApplicationService paramWebApplicationService);
  
  public abstract void redirectServiceToAuthorizedDomain();
}


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/multidomain/IMultiDomainFacade.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */