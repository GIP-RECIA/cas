 package org.esco.portal.cas.services.web;
 
 import java.util.HashMap;
 import java.util.Map;
 import javax.servlet.http.HttpServletRequest;
 import javax.servlet.http.HttpServletResponse;
 import org.esco.cas.CasHelper;
 import org.springframework.beans.factory.InitializingBean;
 import org.springframework.util.Assert;
 import org.springframework.util.StringUtils;
 import org.springframework.web.servlet.ThemeResolver;
 import org.springframework.web.servlet.theme.AbstractThemeResolver;
 
 
 
 
 
 
 
 
 
 
 
 
 
 public class MultiDomainThemeResolverAdapter
   implements ThemeResolver, InitializingBean
 {
   private AbstractThemeResolver backingThemeResolver;
   private Map<String, String> themeByDomainMap;
   
   public String resolveThemeName(HttpServletRequest request)
   {
     String resolvedTheme = null;
     
     String backedDefaultTheme = this.backingThemeResolver.getDefaultThemeName();
     resolvedTheme = this.backingThemeResolver.resolveThemeName(request);
     
     if ((StringUtils.hasText(resolvedTheme)) || (resolvedTheme.equals(backedDefaultTheme)))
     {
       String mdResolvedTheme = resolveMultiDomainTheme(request);
       if (StringUtils.hasText(mdResolvedTheme)) {
         resolvedTheme = mdResolvedTheme;
       }
     }
     
     return resolvedTheme;
   }
   
 
 
 
 
 
 
 
   protected String resolveMultiDomainTheme(HttpServletRequest request)
   {
     String mdResolvedTheme = null;
     
     String serviceId = request.getParameter("service");
     
     String domainName = null;
     if (StringUtils.hasText(serviceId))
     {
       domainName = CasHelper.extractDomainName(serviceId);
     }
     if (!StringUtils.hasText(domainName))
     {
       domainName = request.getServerName();
     }
     
 
     mdResolvedTheme = (String)this.themeByDomainMap.get(domainName);
     
     return mdResolvedTheme;
   }
   
   public void setThemeName(HttpServletRequest request, HttpServletResponse response, String themeName)
   {
     this.backingThemeResolver.setThemeName(request, response, themeName);
   }
   
   public void afterPropertiesSet() throws Exception
   {
     Assert.notNull(this.backingThemeResolver, "Backing ThemeResolver wasn't injected !");
     Assert.notEmpty(this.themeByDomainMap, "Theme by Domain name Map wasn't injected or is empty !");
   }
   
   public AbstractThemeResolver getBackingThemeResolver() {
     return this.backingThemeResolver;
   }
   
   public void setBackingThemeResolver(AbstractThemeResolver backingThemeResolver)
   {
     this.backingThemeResolver = backingThemeResolver;
   }
   
   public Map<String, String> getThemeByDomainMap() {
     return this.themeByDomainMap;
   }
   
   public void setThemeByDomainMap(Map<String, String> themeByDomainMap) {
     this.themeByDomainMap = new HashMap(themeByDomainMap);
   }
   
   public void addThemeByDomainMap(Map<String, String> themeByDomainMap) {
     this.themeByDomainMap.putAll(themeByDomainMap);
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/portal/cas/services/web/MultiDomainThemeResolverAdapter.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */