<%@ page pageEncoding="UTF-8" %>
<%@ page contentType="text/html; charset=UTF-8" %>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<jsp:directive.include file="includes/top.jsp" />

<%--Logout iframes --%>
<c:if test="${not empty idpsLogoutUrl}">
	<c:forEach items="${idpsLogoutUrl}" var="idpLogoutUrl" >
		<iframe class="idpLogout" style="display: none; visibility: hidden;" 
			src="${idpLogoutUrl}">
		</iframe>
	</c:forEach>
</c:if>

<c:if test="${not empty samlCreds && not empty samlCreds.authenticationStatus && samlCreds.authenticationStatus.statusCode != 'success.authentication.saml.email'}">
	<%-- Error while saml auth --%>
	<div id="information" class="errors">
		<p>
			<spring:message code="wayf.saml.auth.error" />
		</p>
	</div>
</c:if>

<div id="wayf">
	
	<h1 id ="title">
		<spring:message code="wayf.welcome" />
	</h1>
	
	<p id="instructions">
		<spring:message code="wayf.instructions" />
	</p>
			
	<div class="idpsList">
		
		<c:forEach items="${wayfConfig.idpsConfig}" var="idpConfig" >
		<div id="${idpConfig.id}">
			<spring:message var="escapedFullUrl" text="${baseIdpSelectGetUrl}${idpConfig.id}" htmlEscape="true" />
			<a class="idpItem" href="${escapedFullUrl}">
				<span class="float-left">
					<span class="idpPicture" onclick="redirectToIdp('${idpConfig.id}');">
						<img src="${idpConfig.pictureUrl}" alt="<spring:message code="${idpConfig.description}" />" /> 
					</span>
				
					<span class="idpDescription">
						<span>
							<spring:message code="${idpConfig.description}" />
						</span>
					</span>
				</span>
			</a>
		</div>
		</c:forEach>
		
		<div class="clear"></div>
	</div>
	
</div>

<script type="text/javascript" src="<c:url value="/js/wayf.js" />"></script>

<jsp:directive.include file="includes/bottom.jsp" />
