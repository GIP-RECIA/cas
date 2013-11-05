<%--

    Licensed to Jasig under one or more contributor license
    agreements. See the NOTICE file distributed with this work
    for additional information regarding copyright ownership.
    Jasig licenses this file to you under the Apache License,
    Version 2.0 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a
    copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on
    an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied. See the License for the
    specific language governing permissions and limitations
    under the License.

--%>

<jsp:directive.include file="includes/top.jsp" />

		<%-- 		
		<div id="msg" class="success">
			<h2><spring:message code="screen.logout.header" /></h2>

			<p><spring:message code="screen.logout.success" /></p>
			<p><spring:message code="screen.logout.security" /></p>
		</div> 
		--%>
		
		<div id="loadingMsg" class="msg">
			<h2>
				<spring:message code="screen.logout.loading" />
			</h2>
			
			<img class="loadingImg" src='<spring:url value="/themes/commun/images/loading.gif" />' alt="Loading..." />
			
			<br />
			<br />
			
			<spring:message code="screen.logout.timeout" />
		</div>
		
		<div id="logoutMsg" class="msg">
			<h2>
				<spring:message code="screen.logout.finished" />
			</h2>
			
			<br />
			<br />
			<br />
			
			<a href="/portail/">Retour au portail ENT.</a>
			
			<br />
			<br />
			<br />
		</div>
		
		<%--Logout iframes --%>
		<c:if test="${not empty idpsLogoutUrl}">
			<c:forEach items="${idpsLogoutUrl}" var="idpLogoutUrl" >
				<iframe class="logout" style="display: none; visibility: hidden;" 
					src="${idpLogoutUrl}" onload="startTimerBeforeRedirect(this);">
				</iframe>
			</c:forEach>
		</c:if>
		
		<script type="text/javascript">
			var callCount = 0;
			var logoutIframeCount = 0;
		
			<%--
			/**
			 * Delete a Cookie
			 * @param key name of the cookie
			 */
			function deleteCookie(key, path, domain)
			{
			  // Delete a cookie by setting the date of expiry to yesterday
			  date = new Date();
			  date.setDate(date.getDate() -1);
			  var cookie = escape(key) + '=;expires=' + date + ';path=' + path + ';domain=' + domain;
			  document.cookie = cookie;
			}
		
			deleteCookie("portail-ent", "/", ".giprecia.org");
   			deleteCookie("portail-ent", "/", ".netocentre.fr");
			--%>
			
			function redirectToService() {
				var serviceUrl = "${param.service}";

				if (serviceUrl != null && serviceUrl != "") {
					document.location = serviceUrl;
					return;
				}
				
				// Backward compatibility CAS2 
				var urlUrl = "${param.url}"; 
				if (urlUrl != null && urlUrl != "") {
					document.location = urlUrl;
					return;
				}
				
				var loadingMsg = document.getElementById("loadingMsg");
				var logoutMsg = document.getElementById("logoutMsg");
				
				loadingMsg.style.display="none";
				logoutMsg.style.display="block";
			}
			
			// Fonction de redirection vers la page d'index apres 1sec 
			function startTimerBeforeRedirect(obj) {
				// Wait for all iframes loading  
				callCount++;
				if (logoutIframesScriptInited != null && logoutIframeCount <= callCount) {
					var fn = redirectToService;
					setTimeout(fn, 1000);
				}
			}
		
			// Bind redirectToIndex() with all logout iframes onload event 
			var iframes = document.getElementsByTagName("iframe");
			var logoutIframesScriptInited = true;
			
			if (iframes != null) {
				//var fn = startTimerBeforeRedirect;
				for (var k = 0; k < iframes.length; k++) {
					var iframe = iframes[k];
					if (iframe != null && "logout" == iframe.className) {
						logoutIframeCount++;
						// BUG IE7: fire event directly in html tag ! 
						//iframe.onload = startTimerBeforeRedirect;
					}
				}
			}
			
			if (iframes == null || iframes.length == 0) {
				// No logout iframes registered : launch redirection ! 
				startTimerBeforeRedirect();
			}
			
			
		</script>
		
<jsp:directive.include file="includes/bottom.jsp" />