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
 * @author Joseph Brislin
 * @created 2012
 */ --->
<cfcomponent displayname="DatabaseAuthenticator" extends="BaseAuthenticator" implements="cfesapi.org.owasp.esapi.Authenticator" output="false"
             hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a database that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository.">

   	<cffunction access="public" returntype="void" name="loadUsersIfNecessary" output="false"
	            hint="Load users if they haven't been loaded in a while.">
		<cfset var local = {}/>

		<cfscript>
			// Retrieve last modified date from database for reference periods
			var _lastModified = ormExecuteQuery("select max(dateModified) from users",{},true);
			if( isNull(_lastModified) ) _lastModified = CreateDateTime(1970, 01, 01, 00, 00, 00); // Default to 01/01/1900 00:00:00

			var userDBLastModified = DateDiff("s", DateConvert("utc2Local", "January 1 1970 00:00"), _lastModified); // Convert to Epoch time to compare with getTickCount()
			
			// We only check at most every checkInterval milliseconds
			local.now = getTickCount();
			if( local.now - instance.lastChecked < instance.checkInterval ){
				return;
			}
			instance.lastChecked = local.now;

			if( instance.lastModified != 0 && instance.lastModified <= userDBLastModified ){
				return;
			}

			try{
				instance.userDB = entityLoad("users");
				loadUsersImmediately();
			}catch(Any e){
				try{
					instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Could not load users from " & entityNew("users").getDbdata().databasename, e);
				}catch(Any e){
					instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Could not load users from database. Fatal Error. ", e);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="loadUsersImmediately" output="false"
	            hint="file was touched so reload it">
		<cfset var local = {}/>

		<cfscript>
			instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Loading users from database");

			try {
				local.map = {};
				// load each user into local map for use with security project
				for(var _user in instance.userDB){
					local.user = _createUser(_user);

					if(local.map.containsKey(javaCast("long", user.getAccountId()))) {
						instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem in user file. Skipping duplicate user: " & local.user);
					}
					local.map.put( local.user.getAccountID(), local.user );
				}

				instance.userMap = local.map;
				
				instance.lastModified = getTickCount();
				instance.logger.trace(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "User file reloaded: " & local.map.size());
			}
			catch(java.lang.Exception e) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Failure loading user database: " & entityNew("users").getDbdata().databasename, e);
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
			// saveUsers();
			save( local.user ); // do not need to resave all users like fileBasedAuthentication - only save individual user
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="DefaultUser" name="_createUser" output="false"
	            hint="Create a new user with all attributes from a String.  The format is: * accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count - This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.">
		<cfargument required="true" type="Any" name="record" hint="parameters to set as attributes for the new User."/>

		<cfset var local = {}/>

		<cfscript>
			local.accountIdString = arguments.record.getAccountId();
			local.accountId = javaCast("long", local.accountIdString);
			local.accountName = arguments.record.getAccountName();
			verifyAccountNameStrength(local.accountName);
			local.user = newComponent("cfesapi.org.owasp.esapi.reference.DefaultUser").init(instance.ESAPI, local.accountName);
			local.user.accountId = local.accountId;
			local.password = arguments.record.getHashedPassword();
			verifyPasswordStrength(newPassword=local.password, user=local.user);
			setHashedPassword(local.user, local.password);

			local.roles = arguments.record.getRoles();
			for(local.i = 1; local.i <= arrayLen(local.roles); local.i++) {
				local.role = local.roles[local.i].getRoleKey();
				if(local.role != "") {
					local.user.addRole(local.role);
				}
			}
			if(arguments.record.getLocked() != "unlocked") {
				local.user.lock();
			}
			if(arguments.record.getEnabled() == "enabled") {
				local.user.enable();
			}
			else {
				local.user.disable();
			}

			local.user.setScreenName( arguments.record.getFirstName() & " " & arguments.record.getLastName() );

			// generate a new csrf token
			local.user.resetCSRFToken();

			setOldPasswordHashes(local.user, arguments.record.getOldPasswordHashes());
			local.user.setLastHostAddress(iif("unknown" == arguments.record.getLastHostAddress(), de(""), de(arguments.record.getLastHostAddress())));
			local.user.setLastPasswordChangeTime(newJava("java.util.Date").init(javaCast("long", arguments.record.getLastPasswordChangeTime())));
			local.user.setLastLoginTime(newJava("java.util.Date").init(javaCast("long", arguments.record.getLastLoginTime())));
			local.user.setLastFailedLoginTime(newJava("java.util.Date").init(javaCast("long", arguments.record.getLastFailedLoginTime())));
			local.user.setExpirationTime(newJava("java.util.Date").init(javaCast("long", arguments.record.getExpirationTime())));
			local.user.setFailedLoginCount(int(arguments.record.getFailedLoginCount()));
			return local.user;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="saveUsers" output="false"
	            hint="Saves the user database to the file system. In this implementation you must call save to commit any changes to the user file. Otherwise changes will be lost when the program ends.">
		<cfset var local = {}/>

		<cfscript>
			for(var _user in instance.userDB){
				
				if( !_user.isAnonymous() ) {
					save( _user );
				}
				else {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Problem saving user", "Skipping save of user " & local.accountName);
					throwError(local.exception);
				}
			}
			abort;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="save" output="false"
	            hint="Returns a line containing properly formatted information to save regarding the user">
		<cfargument required="true" type="DefaultUser" name="user" hint="the User to save"/>

		<cfscript>
			var local = {};
			local.user = {};

			transaction{

				var _user = entityLoad( "users", { accountId = arguments.user.getAccountId() }, true );

				// load new entity if user not found
				if( isNull(_user) ){
					_user = entityNew("users");
					_user.setAccountId( arguments.user.getAccountId() );
				} 

				local.user.accountName = arguments.user.getAccountName();
				local.user.hashedPassword = getHashedPassword(arguments.user);
				local.user.locked = iif( arguments.user.isLocked(), de("locked"), de("unlocked") );
				local.user.enabled = iif( arguments.user.isEnabled(), de("enabled"), de("disabled") );
				local.user.csrfToken = arguments.user.getCSRFToken();
				local.user.lastHostAddress = arguments.user.getLastHostAddress();
				local.user.lastPasswordChangeTime = JavaCast( "Long", arguments.user.getLastPasswordChangeTime().getTime() );
				local.user.lastLoginTime = JavaCast( "Long", arguments.user.getLastLoginTime().getTime() );
				local.user.lastFailedLoginTime = JavaCast( "Long", arguments.user.getLastFailedLoginTime().getTime() );
				local.user.expirationTime = JavaCast( "Long", arguments.user.getExpirationTime().getTime() );
				local.user.failedLoginCount = JavaCast( "int", arguments.user.getFailedLoginCount() );
				
				_user.populate( local.user );

				// add security roles
				var _roles = [];

				for( _userRole in arguments.user.getRoles() )
				{	
					_role = EntityLoad( "Roles", { roleKey = _userRole }, true );
					if( !isNull(_role) ) _roles.add( _role );
				}
		
				_user.setRoles( _roles );

				// clear out current old password
				_user.removeAllOldPasswordHashes();

				// set to new old password hashes
				for( _passwordHash in getOldPasswordHashes(arguments.user) )
				{
					_pass = entityNew("users_oldPasswords");
					_pass.setOldPassword( _passwordHash );
					_user.addOldPassword( _pass );
				}

				try{
					_user.save();
				}catch(Any e){
					transaction action="rollback";
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Problem saving user", "Error saving user " & arguments.user.getAccountName());
					throwError(local.exception);
				}
				
				// check to make sure accountID is set properly
				if( _user.getAccountId() == "" ){
					transaction action="rollback";
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Problem saving user", "Skipping save of user " & arguments.user.getAccountName());
					throwError(local.exception);
				}
				
			}
			
		</cfscript>

	</cffunction>

</cfcomponent>