package org.esco.cas.services;

import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.CasHelper;
import org.esco.cas.multidomain.IMultiDomainConfig;
import org.jasig.cas.authentication.principal.Service;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class MultiDomainService extends IndexRedirectService implements InitializingBean {
  private static final long serialVersionUID = 1022678474253813028L;
  private static final Log LOGGER = LogFactory.getLog(MultiDomainService.class);

  private transient IMultiDomainConfig multiDomainConfig;

  public String getTheme()
  {
    return this.multiDomainConfig.getCurrentTheme();
  }

  public boolean matches(Service service) {
    boolean result = false;

    String baseServiceId = super.getServiceId();
    String serviceDomain = null;
    if (service != null) {
      serviceDomain = CasHelper.extractDomainName(service.getId());

      if ((serviceDomain != null) && (this.multiDomainConfig.getDomains().contains(serviceDomain))) {

        String adaptedServiceId = CasHelper.replaceUrlDomain(baseServiceId, serviceDomain);

        Pattern p = Pattern.compile(adaptedServiceId, 2);
        Matcher m = p.matcher(service.getId());
        result = m.find();

        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug(String.format("Is M-D service (%d) matching between [%s] and [%s] returned [%s].", new Object[] { Long.valueOf(getId()), adaptedServiceId, service.getId(), Boolean.valueOf(result) }));
        }

      }
      else if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(String.format("M-D Service (%1$d) [%2$s] is not authorized for service's domain name of [%3$s] returned [%4$s].", new Object[] { Long.valueOf(getId()), baseServiceId, service.getId(), Boolean.valueOf(result) }));
      }
    }

    return result;
  }

  public String getServiceId() {
    String resultId = null;

    String baseServiceId = super.getServiceId();

    String currentServiceId = this.multiDomainConfig.getCurrentServiceId(baseServiceId);
    if (StringUtils.hasText(currentServiceId)) {
      resultId = currentServiceId;
    } else {
      resultId = baseServiceId;
    }
    return resultId;
  }

  public String getIndexRedirectUrl() {
    String redirectionUrl = this.multiDomainConfig.getOverrideIndexRedirectUrl();

    if (!StringUtils.hasText(redirectionUrl))
    {
      String currentDomain = this.multiDomainConfig.getCurrentDomainName();
      redirectionUrl = CasHelper.replaceUrlDomain(super.getIndexRedirectUrl(), currentDomain);
    }

    return redirectionUrl;
  }

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.multiDomainConfig, "A multidomain Service need a configuration !");

    LOGGER.info(String.format("Multi-domain service [%s] loaded with base service Id = [%s], authorized domains(%s) = [%s], allowed attributes(%s) = [%s].", new Object[] { Long.valueOf(getId()), getServiceId(), Integer.valueOf(this.multiDomainConfig.getDomains().size()), this.multiDomainConfig.getDomains(), Integer.valueOf(getAllowedAttributes().size()), getAllowedAttributes() }));
  }

  public IMultiDomainConfig getMultiDomainConfig()  {
    return this.multiDomainConfig;
  }

  public void setMultiDomainConfig(IMultiDomainConfig multiDomainConfig) {
    this.multiDomainConfig = multiDomainConfig;
  }
}