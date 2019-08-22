 package org.esco.cas.multidomain.impl;
 
 import java.util.HashSet;
 import java.util.Map;
 import java.util.Set;
 import javax.servlet.http.HttpServletRequest;
 import org.esco.cas.CasHelper;
 import org.esco.cas.multidomain.IMultiDomainConfig;
 import org.springframework.beans.factory.InitializingBean;
 import org.springframework.util.Assert;
 import org.springframework.util.CollectionUtils;
 import org.springframework.util.StringUtils;
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 public class MultiDomainConfig
   implements IMultiDomainConfig, InitializingBean
 {
   private Map<String, String> domainAndThemeConf;
   private Map<String, String> indexRedirectUrlOverrideConfig;
   
   public String getCurrentServiceId(String baseServiceId)
   {
     String serviceId = null;
     if (StringUtils.hasText(baseServiceId))
     {
       String domain = getCurrentDomainName();
       if (StringUtils.hasText(domain)) {
         serviceId = CasHelper.replaceUrlDomain(baseServiceId, domain);
       }
     }
     
     return serviceId;
   }
   
   public String getCurrentTheme()
   {
     String theme = null;
     
     String serviceDomain = getCurrentDomainName();
     if (StringUtils.hasText(serviceDomain)) {
       theme = (String)this.domainAndThemeConf.get(serviceDomain);
     }
     
 
     if (!StringUtils.hasText(theme)) {
       HttpServletRequest request = CasHelper.retrieveCurrentRequest();
       if (request != null) {
         theme = (String)this.domainAndThemeConf.get(request.getServerName());
       }
     }
     
     return theme;
   }
   
   public String getCurrentDomainName()
   {
     String serviceDomain = CasHelper.getServiceDomainName();
     
     String domainName = null;
     if ((StringUtils.hasText(serviceDomain)) && (getDomains().contains(serviceDomain)))
     {
       domainName = serviceDomain;
     }
     
     return domainName;
   }
   
   public Set<String> getDomains()
   {
     return new HashSet(this.domainAndThemeConf.keySet());
   }
   
   public String getOverrideIndexRedirectUrl()
   {
     String indexRedirectUrl = null;
     
     if (!CollectionUtils.isEmpty(this.indexRedirectUrlOverrideConfig)) {
       String currentDomain = getCurrentDomainName();
       indexRedirectUrl = (String)this.indexRedirectUrlOverrideConfig.get(currentDomain);
     }
     
     return indexRedirectUrl;
   }
   
   public void afterPropertiesSet() throws Exception
   {
     Assert.notEmpty(this.domainAndThemeConf, "The multidomain configuration is not properly configured !");
   }
   
 
 
 
 
   public void setDomainAndThemeConf(Map<String, String> domainAndThemeConf)
   {
     this.domainAndThemeConf = domainAndThemeConf;
   }
   
 
 
 
 
 
   public void setIndexRedirectUrlOverrideConfig(Map<String, String> indexRedirectUrlConfig)
   {
     this.indexRedirectUrlOverrideConfig = indexRedirectUrlConfig;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/multidomain/impl/MultiDomainConfig.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */