<!---
	/**
	* OWASP Enterprise Security API (ESAPI)
	* 
	* This file is part of the Open Web Application Security Project (OWASP)
	* Enterprise Security API (ESAPI) project. For details, please see
	* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
	*
	* Copyright (c) 2011 - The OWASP Foundation
	* 
	* The ESAPI is published by OWASP under the BSD license. You should read and accept the
	* LICENSE before you use, modify, and/or redistribute this software.
	* 
	* @author Damon Miller
	* @created 2011
	*/
	--->
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>
			CFESAPI Demo Logged In 
		</title>
	</head>
	<body>
		<cfinclude template="/cfesapi/demo/fba/includes/header.cfm" />
		<h2>
			Members Only
		</h2>
		<p>
			This is page 1 of the memeber only area 
		</p>
		<p>
			Congratulations!!! If you are seeing this page than you have successfully used CFESAPI to login. 
		</p>
		<p>
			<a href="page2.cfm">
				Member Only Page 2 - Test Persistence of User 
			</a>
		</p>
	</body>
</html>
