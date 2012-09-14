<!--- /**
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
 */ --->
<cfcomponent displayname="FileBasedAuthenticator" extends="BaseAuthenticator" implements="cfesapi.org.owasp.esapi.Authenticator" output="false"
             hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text file that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository. This reference implementation captures information about users in a simple text file format that contains user information separated by the pipe '|' character.">

	<cffunction access="private" returntype="void" name="loadUsersIfNecessary" output="false"
	            hint="Load users if they haven't been loaded in a while.">
		<cfset var local = {}/>

		<cfscript>
			if(!isObject(instance.userDB)) {
				instance.userDB = instance.ESAPI.securityConfiguration().getResourceFile("users.txt");
			}
			if(!isObject(instance.userDB)) {
				instance.userDB = newJava("java.io.File").init(newJava("java.lang.System").getProperty("user.home") & "/esapi", "users.txt");
				try {
					if(!instance.userDB.createNewFile()) {
						throwError(newJava("java.io.IOException").init("Unable to create the user file"));
					}
					instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Created " & instance.userDB.getAbsolutePath());
				}
				catch(java.io.IOException e) {
					instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Could not create " & instance.userDB.getAbsolutePath(), e);
				}
			}

			// We only check at most every checkInterval milliseconds
			local.now = getTickCount();
			if(local.now - instance.lastChecked < instance.checkInterval) {
				return;
			}
			instance.lastChecked = local.now;

			if(instance.lastModified == instance.userDB.lastModified()) {
				return;
			}
			loadUsersImmediately();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="loadUsersImmediately" output="false"
	            hint="file was touched so reload it">
		<cfset var local = {}/>

		<cfscript>
			instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Loading users from " & instance.userDB.getAbsolutePath());

			local.reader = "";
			try {
				local.map = {};
				local.reader = newJava("java.io.BufferedReader").init(newJava("java.io.FileReader").init(instance.userDB));
				local.line = local.reader.readLine();
				while(structKeyExists(local, "line")) {
					if(local.line.length() > 0 && local.line.charAt(0) != chr(35)) {
						local.user = _createUser(local.line);
						if(local.map.containsKey(javaCast("long", local.user.getAccountId()))) {
							instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in user file. Skipping duplicate user: " & local.user);
						}
						local.map.put(local.user.getAccountId(), local.user);
					}
					local.line = local.reader.readLine();
				}
				instance.userMap = local.map;
				instance.lastModified = getTickCount();
				instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "User file reloaded: " & local.map.size());
			}
			catch(java.lang.Exception e) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure loading user file: " & instance.userDB.getAbsolutePath(), e);
			}
			try {
				if(structKeyExists(local, "reader") && isObject(local.reader)) {
					local.reader.close();
				}
			}
			catch(java.io.IOException e) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure closing user file: " & instance.userDB.getAbsolutePath(), e);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="createUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>
		<cfargument required="true" type="String" name="password1"/>
		<cfargument required="true" type="String" name="password2"/>

		<cfset var local = {}/>

		<cfscript>
			loadUsersIfNecessary();
			if(trim(arguments.accountName) == "") {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Account creation failed", "Attempt to create user with blank accountName");
				throwError(local.exception);
			}
			if(isObject(getUserByAccountName(arguments.accountName))) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Account creation failed", "Duplicate user creation denied for " & arguments.accountName);
				throwError(local.exception);
			}
			
			verifyAccountNameStrength(arguments.accountName);

			if(trim(arguments.password1) == "") {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "Attempt to create account " & arguments.accountName & " with a blank password");
				throwError(local.exception);
			}

			local.user = newComponent("cfesapi.org.owasp.esapi.reference.DefaultUser").init(instance.ESAPI, arguments.accountName);

			verifyPasswordStrength(newPassword=arguments.password1, user=local.user);

			if(!arguments.password1.equals(arguments.password2)) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Passwords do not match", "Passwords for " & arguments.accountName & " do not match");
				throwError(local.exception);
			}

			try {
				setHashedPassword(local.user, hashPassword(arguments.password1, arguments.accountName));
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Internal error", "Error hashing password for " & arguments.accountName, ee);
				throwError(local.exception);
			}
			instance.userMap.put(local.user.getAccountId(), local.user);
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "New user created: " & arguments.accountName);
			
			// FIXME: need to rethink this for Database Authentication - if large number of users, we will not want to resave all users
			saveUsers();
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="DefaultUser" name="_createUser" output="false"
	            hint="Create a new user with all attributes from a String.  The format is: * accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count - This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.">
		<cfargument required="true" type="String" name="line" hint="parameters to set as attributes for the new User."/>

		<cfset var local = {}/>

		<cfscript>
			local.parts = line.split(" *\| *");
			local.accountIdString = local.parts[1];
			local.accountId = javaCast("long", local.accountIdString);
			local.accountName = local.parts[2];

			verifyAccountNameStrength(local.accountName);
			local.user = newComponent("cfesapi.org.owasp.esapi.reference.DefaultUser").init(instance.ESAPI, local.accountName);
			local.user.accountId = local.accountId;

			local.password = local.parts[3];
			verifyPasswordStrength(newPassword=local.password, user=local.user);
			setHashedPassword(local.user, local.password);

			local.roles = local.parts[4].toLowerCase().split(" *, *");
			for(local.i = 1; local.i <= arrayLen(local.roles); local.i++) {
				local.role = local.roles[local.i];
				if(local.role != "") {
					local.user.addRole(local.role);
				}
			}
			if(local.parts[5] != "unlocked") {
				local.user.lock();
			}
			if(local.parts[6] == "enabled") {
				local.user.enable();
			}
			else {
				local.user.disable();
			}

			// generate a new csrf token
			local.user.resetCSRFToken();

			setOldPasswordHashes(local.user, local.parts[7].split(" *, *"));
			local.user.setLastHostAddress(iif("unknown" == local.parts[8], de(""), de(local.parts[8])));
			local.user.setLastPasswordChangeTime(newJava("java.util.Date").init(javaCast("long", local.parts[9])));
			local.user.setLastLoginTime(newJava("java.util.Date").init(javaCast("long", local.parts[10])));
			local.user.setLastFailedLoginTime(newJava("java.util.Date").init(javaCast("long", local.parts[11])));
			local.user.setExpirationTime(newJava("java.util.Date").init(javaCast("long", local.parts[12])));
			local.user.setFailedLoginCount(int(local.parts[13]));
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="saveUsers" output="false"
	            hint="Saves the user database to the file system. In this implementation you must call save to commit any changes to the user file. Otherwise changes will be lost when the program ends.">
		<cfset var local = {}/>

		<cfscript>
			local.writer = "";
			try {
				local.writer = newJava("java.io.PrintWriter").init(newJava("java.io.FileWriter").init(instance.userDB));
				local.writer.println("## This is the user file associated with the ESAPI library from http://www.owasp.org");
				local.writer.println("## accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
				local.writer.println();
				_saveUsers(local.writer);
				local.writer.flush();
				instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "User file written to disk");
			}
			catch(java.io.IOException e) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem saving user file " & instance.userDB.getAbsolutePath(), e);
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Internal Error", "Problem saving user file " & instance.userDB.getAbsolutePath(), e);
				throwError(local.exception);
			}
			if(isObject(local.writer)) {
				local.writer.close();
				instance.lastModified = instance.userDB.lastModified();
				instance.lastChecked = instance.lastModified;
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="_saveUsers" output="false"
	            hint="Save users.">
		<cfargument required="true" name="writer" hint="the print writer to use for saving"/>

		<cfset var local = {}/>

		<cfscript>
			local.o = getUserNames();
			for(local.i = 1; local.i <= arrayLen(local.o); local.i++) {
				local.accountName = local.o[local.i];
				local.u = getUserByAccountName(local.accountName);
				if(structKeyExists(local, "u") && !local.u.isAnonymous()) {
					arguments.writer.println(save(local.u));
				}
				else {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Problem saving user", "Skipping save of user " & local.accountName);
					throwError(local.exception);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="save" output="false"
	            hint="Returns a line containing properly formatted information to save regarding the user">
		<cfargument required="true" type="DefaultUser" name="user" hint="the User to save"/>

		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.sb.append(arguments.user.getAccountId());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getAccountName());
			local.sb.append(" | ");
			local.sb.append(getHashedPassword(arguments.user));
			local.sb.append(" | ");
			local.sb.append(arrayToList(arguments.user.getRoles()));
			local.sb.append(" | ");
			local.sb.append(iif(arguments.user.isLocked(), de("locked"), de("unlocked")));
			local.sb.append(" | ");
			local.sb.append(iif(arguments.user.isEnabled(), de("enabled"), de("disabled")));
			local.sb.append(" | ");
			local.sb.append(arrayToList(getOldPasswordHashes(arguments.user)));
			local.sb.append(" | ");
			local.sb.append(arguments.user.getLastHostAddress());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getLastPasswordChangeTime().getTime());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getLastLoginTime().getTime());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getLastFailedLoginTime().getTime());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getExpirationTime().getTime());
			local.sb.append(" | ");
			local.sb.append(arguments.user.getFailedLoginCount());
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

</cfcomponent>