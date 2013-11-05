function redirectToIdp(idpId) {
	document.location = getIdpUrl(idpId);
}

function getIdpUrl(idpId) {
	var idpUrl;
	
	if (!isBlank(idpId)) {
		var docLocation = document.location.href;	
		if (docLocation.indexOf("?") > -1) {
			idpUrl = docLocation + '&idpId=' + idpId;
		} else {
			idpUrl = docLocation + '?idpId=' + idpId;
		}
	}
	
	return idpUrl;
}

function getIdpId() {
	var idpId = document.getElementById('idpId').value;
	return idpId;
}

function isBlank(str) {
    return (!str || /^\s*$/.test(str));
}
