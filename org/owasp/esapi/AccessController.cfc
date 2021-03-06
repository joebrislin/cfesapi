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
<cfinterface hint="The AccessController interface defines a set of methods that can be used in a wide variety of applications to enforce access control. In most applications, access control must be performed in multiple different locations across the various application layers. This class provides access control for URLs, business functions, data, services, and files. The implementation of this interface will need to access the current User object (from Authenticator.getCurrentUser()) to determine roles or permissions. In addition, the implementation will also need information about the resources that are being accessed. Using the user information and the resource information, the implementation should return an access control decision. Implementers are encouraged to implement the ESAPI access control rules, like assertAuthorizedForFunction() using existing access control mechanisms, such as methods like isUserInRole() or hasPrivilege(). While powerful, methods like isUserInRole() can be confusing for developers, as users may be in multiple roles or possess multiple overlapping privileges. Direct use of these finer grained access control methods encourages the use of complex boolean tests throughout the code, which can easily lead to developer mistakes. The point of the ESAPI access control interface is to centralize access control logic behind easy to use calls like assertAuthorized() so that access control is easy to use and easy to verify.">

	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false" hint="isAuthorized executes the AccessControlRule that is identified by key and listed in the resources/ESAPI-AccessControlPolicy.xml file. It returns true if the AccessControlRule decides that the operation should be allowed. Otherwise, it returns false. Any exception thrown by the AccessControlRule must result in false. If key does not map to an AccessControlRule, then false is returned. Developers should call isAuthorized to control execution flow. For example, if you want to decide whether to display a UI widget in the browser using the same logic that you will use to enforce permissions on the server, then isAuthorized is the method that you want to use.">
		<cfargument type="String" name="key" required="true" hint="key maps to AccessControlPolicy AccessControlRules AccessControlRule name='key'">
		<cfargument type="Struct" name="runtimeParameter" required="true" hint="runtimeParameter can contain anything that the AccessControlRule needs from the runtime system.">
	</cffunction>


	<cffunction access="public" returntype="void" name="assertAuthorized" output="false" hint="assertAuthorized executes the AccessControlRule that is identified by key and listed in the resources/ESAPI-AccessControlPolicy.xml file. It does nothing if the AccessControlRule decides that the operation should be allowed. Otherwise, it throws an org.owasp.esapi.errors.AccessControlException. Any exception thrown by the AccessControlRule will also result in an AccesControlException. If key does not map to an AccessControlRule, then an AccessControlException  is thrown. Developers should call {@code assertAuthorized} to enforce privileged access to the system. It should be used to answer the question: 'Should execution continue.' Ideally, the call to assertAuthorized should be integrated into the application framework so that it is called automatically.">
		<cfargument type="String" name="key" required="true" hint="key maps to AccessControlPolicy AccessControlRules AccessControlRule name='key'">
		<cfargument type="Struct" name="runtimeParameter" required="true" hint="runtimeParameter can contain anything that the AccessControlRule needs from the runtime system.">
	</cffunction>

</cfinterface>
