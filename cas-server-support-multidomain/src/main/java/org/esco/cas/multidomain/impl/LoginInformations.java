 package org.esco.cas.multidomain.impl;
 
 import java.util.Collection;
 import org.springframework.util.StringUtils;
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 public class LoginInformations
 {
   private Collection<String> authorizedDomains;
   private String sessionUai;
   private String distinguishedName;
   
   public boolean checkServiceDomainName(String domainName)
   {
     return (StringUtils.hasText(domainName)) && (this.authorizedDomains.contains(domainName));
   }
   
 
 
 
 
   Collection<String> getAuthorizedDomains()
   {
     return this.authorizedDomains;
   }
   
 
 
 
 
   public void setAuthorizedDomains(Collection<String> authorizedDomains)
   {
     this.authorizedDomains = authorizedDomains;
   }
   
 
 
 
 
   public String getSessionUai()
   {
     return this.sessionUai;
   }
   
 
 
 
 
   public void setSessionUai(String sessionUai)
   {
     this.sessionUai = sessionUai;
   }
   
 
 
 
 
   public String getDistinguishedName()
   {
     return this.distinguishedName;
   }
   
 
 
 
 
   public void setDistinguishedName(String distinguishedName)
   {
     this.distinguishedName = distinguishedName;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/multidomain/impl/LoginInformations.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */