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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.AccessController" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";

		instance.ruleMap = {};
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.AccessController" name="init">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("DefaultAccessController");

			local.policyDescriptor = newComponent("cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader").init(instance.ESAPI);
			local.policyDTO = local.policyDescriptor.load();
			instance.ruleMap = local.policyDTO.getAccessControlRules();

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false">
		<cfargument type="String" name="key" required="true"/>
		<cfargument type="Struct" name="runtimeParameter" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				local.rule = instance.ruleMap.get(arguments.key);
				if(!structKeyExists(local, "rule")) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "AccessControlRule was not found for key: " & arguments.key));
				}
				if(instance.logger.isDebugEnabled()) {
					instance.logger.debug(Logger.EVENT_SUCCESS, 'Evaluating Authorization Rule "' & arguments.key & '" Using class: ' & local.rule.getClass().getCanonicalName());
				}
				return local.rule.isAuthorized(arguments.runtimeParameter);
			}
			catch(java.lang.Exception e) {
				try {
					//Log the exception by throwing and then catching it.
					//TODO figure out what which string goes where.
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "An unhandled Exception was caught, so access is denied.", e));
				}
				catch(cfesapi.org.owasp.esapi.errors.AccessControlException ace) {
					//the exception was just logged. There's nothing left to do.
				}
				return false;//fail closed
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorized" output="false">
		<cfargument type="String" name="key" required="true"/>
		<cfargument type="Struct" name="runtimeParameter" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				local.rule = instance.ruleMap.get(arguments.key);
				if(!structKeyExists(local, "rule")) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "AccessControlRule was not found for key: " & arguments.key));
				}
				if(instance.logger.isDebugEnabled()) {
					instance.logger.debug(Logger.EVENT_SUCCESS, 'Asserting Authorization Rule "' & arguments.key & '" Using class: ' & rule.getClass().getCanonicalName());
				}
				local.isAuthorized = local.rule.isAuthorized(arguments.runtimeParameter);
			}
			catch(Exception e) {
				//TODO figure out what which string goes where.
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "An unhandled Exception was caught, so access is denied. AccessControlException.", e));
			}
			if(!local.isAuthorized) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "Access Denied for key: " & arguments.key & " runtimeParameter: " & arguments.runtimeParameter.toString()));
			}
		</cfscript>

	</cffunction>

	<!--- /*** Below this line has been deprecated as of ESAPI 1.6 ***/ --->

	<cffunction access="public" returntype="void" name="assertAuthorizedForData" output="false">
		<cfargument type="String" name="action" required="true"/>
		<cfargument type="any" name="data" required="true"/>

		<cfscript>
			this.assertAuthorized("AC 1.0 Data", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFile" output="false">
		<cfargument type="String" name="filepath" required="true"/>

		<cfscript>
			this.assertAuthorized("AC 1.0 File", arguments);
		</cfscript>

	</cffunction>

	<cffunction accesss="public" returntype="void" name="assertAuthorizedForFunction" output="false">
		<cfargument type="String" name="functionName" required="true"/>

		<cfscript>
			this.assertAuthorized("AC 1.0 Function", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForService" output="false">
		<cfargument type="String" name="serviceName" required="true"/>

		<cfscript>
			this.assertAuthorized("AC 1.0 Service", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForURL" output="false">
		<cfargument type="String" name="url" required="true"/>

		<cfscript>
			this.assertAuthorized("AC 1.0 URL", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForData" output="false">
		<cfargument type="String" name="action" required="true"/>
		<cfargument type="any" name="data" required="true"/>

		<cfscript>
			return this.isAuthorized("AC 1.0 Data", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFile" output="false">
		<cfargument type="String" name="filepath" required="true"/>

		<cfscript>
			return this.isAuthorized("AC 1.0 File", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFunction" output="false">
		<cfargument type="String" name="functionName" required="true"/>

		<cfscript>
			return this.isAuthorized("AC 1.0 Function", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForService" output="false">
		<cfargument type="String" name="serviceName" required="true"/>

		<cfscript>
			return this.isAuthorized("AC 1.0 Service", arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForURL" output="false">
		<cfargument type="String" name="url" required="true"/>

		<cfscript>
			return this.isAuthorized("AC 1.0 URL", arguments);
		</cfscript>

	</cffunction>

</cfcomponent>