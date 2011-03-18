<cfcomponent implements="cfesapi.org.owasp.esapi.HttpSession" output="false">

	<cfscript>
		/* The invalidated. */
		instance.invalidated = false;

		/* The creation time. */
		instance.creationTime = createObject("java", "java.util.Date").getTime();

		/* The accessed time. */
		instance.accessedTime = createObject("java", "java.util.Date").getTime();

		/* The count. */
		if (!structKeyExists(request, "count")) {
			request.count = 1;
		}

		/* The sessionid. */
		instance.sessionid = request.count++;

		/* The attributes. */
		instance.attributes = {};
	</cfscript>

	<cffunction access="public" returntype="MockHttpSession" name="init" output="false" hint="Instantiates a new test http session.">
		<cfargument type="numeric" name="creationTime" required="false" hint="the creation time">
		<cfargument type="numeric" name="accessedTime" required="false" hint="the accessed time">
		<cfscript>
			if (structKeyExists(arguments, "creationTime")) {
				instance.creationTime = arguments.creationTime;
			}
			if (structKeyExists(arguments, "accessedTime")) {
				instance.accessedTime = arguments.accessedTime;
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttribute" output="false">
		<cfargument type="String" name="string" required="true">
		<cfscript>
			return instance.attributes.get( arguments.string );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttributeNames" output="false" hint="java.util.Enumeration">
		<cfscript>
			local.v = createObject("java", "java.util.Vector").init( instance.attributes.keySet() );
			return local.v.elements();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false">
		<cfscript>
			return instance.creationTime;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getId" output="false">
		<cfscript>
			return ""&instance.sessionid;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getInvalidated" output="false" hint="Gets the invalidated.">
		<cfscript>
			return instance.invalidated;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false">
		<cfscript>
			return instance.accessedTime;
		</cfscript>
	</cffunction>

	<!--- getMaxInactiveInterval --->
	<!--- getServletContext --->

	<cffunction access="public" returntype="void" name="invalidate" output="false">
		<cfscript>
			instance.invalidated = true;
		</cfscript>
	</cffunction>

	<!--- isNew --->
	<!--- removeAttribute --->

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="string" required="true">
		<cfargument type="any" name="object" required="true">
		<cfscript>
			instance.attributes.put(arguments.string, arguments.object);
		</cfscript>
	</cffunction>

	<!--- setMaxInactiveInterval --->

	<cffunction access="public" returntype="void" name="setAccessedTime" output="false">
		<cfargument type="numeric" name="time" required="true">
		<cfscript>
			instance.accessedTime = arguments.time;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setCreationTime" output="false">
		<cfargument type="numeric" name="time" required="true">
		<cfscript>
			instance.creationTime = arguments.time;
		</cfscript>
	</cffunction>


</cfcomponent>