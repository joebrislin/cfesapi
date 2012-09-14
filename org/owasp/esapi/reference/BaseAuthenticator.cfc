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
<cfcomponent displayname="BaseAuthenticator" extends="AbstractAuthenticator" output="false"
             hint="Reference implementation of the Authenticator interface. This reference implementation is backed by a simple text file that contains serialized information about users. Many organizations will want to create their own implementation of the methods provided in the Authenticator interface backed by their own user repository. This reference implementation captures information about users in a simple text file format that contains user information separated by the pipe '|' character.">

	<cfscript>
		/**
		 * The logger.
		 */
		instance.logger = "";

		/**
		 * The file that contains the user db
		 */
		instance.userDB = "";

		/**
		 * How frequently to check the user db for external modifications
		 */
		instance.checkInterval = 60 * 1000;

		/**
		 * The last modified time we saw on the user db.
		 */
		instance.lastModified = 0;

		/**
		 * The last time we checked if the user db had been modified externally
		 */
		instance.lastChecked = 0;

		instance.MAX_ACCOUNT_NAME_LENGTH = 250;

		/**
		 * The user map.
		 */
		instance.userMap = {};

		// Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
		instance.passwordMap = {};
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Authenticator" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			super.init(arguments.ESAPI);
			instance.logger = instance.ESAPI.getLogger("Authenticator");
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setHashedPassword" output="false"
	            hint="Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes to be sure that any new passwords are not too similar to old passwords.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the user to associate with the new hash"/>
		<cfargument required="true" type="String" name="hash" hint="the hash to store in the user's password hash list"/>

		<cfset var local = {}/>

		<cfscript>
			local.hashes = getAllHashedPasswords(arguments.user, true);
			arrayPrepend(local.hashes, arguments.hash);
			if(local.hashes.size() > instance.ESAPI.securityConfiguration().getMaxOldPasswordHashes()) {
				local.hashes.remove(local.hashes.size() - 1);
			}
			instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "New hashed password stored for " & arguments.user.getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHashedPassword" output="false"
	            hint="Return the specified User's current hashed password.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="this User's current hashed password will be returned"/>

		<cfset var local = {}/>

		<cfscript>
			local.hashes = getAllHashedPasswords(arguments.user, false);
			if(arrayLen(local.hashes)) {
				return local.hashes[1];
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setOldPasswordHashes" output="false"
	            hint="Set the specified User's old password hashes.  This will not set the User's current password hash.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the User whose old password hashes will be set"/>
		<cfargument required="true" type="Array" name="oldHashes" hint="a list of the User's old password hashes"/>

		<cfset var local = {}/>

		<cfscript>
			local.hashes = getAllHashedPasswords(arguments.user, true);
			if(local.hashes.size() > 1) {
				local.hashes.removeAll(local.hashes.subList(1, local.hashes.size() - 1));
			}
			for(local.i = 1; local.i <= arrayLen(arguments.oldHashes); local.i++) {
				arrayAppend(local.hashes, arguments.oldHashes[local.i]);
			}
			instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllHashedPasswords" output="false"
	            hint="Returns all of the specified User's hashed passwords.  If the User's list of passwords is null, and create is set to true, an empty password list will be associated with the specified User and then returned. If the User's password map is null and create is set to false, an exception will be thrown.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the User whose old hashes should be returned"/>
		<cfargument required="true" type="boolean" name="create" hint="true - if no password list is associated with this user, create one; false - if no password list is associated with this user, do not create one"/>

		<cfset var local = {}/>

		<cfscript>
			local.hashes = instance.passwordMap.get(arguments.user.getAccountId());
			if(structKeyExists(local, "hashes")) {
				return local.hashes;
			}
			if(arguments.create) {
				local.hashes = [];
				instance.passwordMap.put(arguments.user.getAccountId(), local.hashes);
				return local.hashes;
			}
			throwError(newJava("java.lang.RuntimeException").init("No hashes found for " & arguments.user.getAccountName() & ". Is User.hashcode() and equals() implemented correctly?"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getOldPasswordHashes" output="false"
	            hint="Get a List of the specified User's old password hashes.  This will not return the User's current password hash.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="the user whose old password hashes should be returned"/>

		<cfset var local = {}/>

		<cfscript>
			local.hashes = getAllHashedPasswords(arguments.user, false);
			if(local.hashes.size() > 1) {
				return duplicate(listToArray(listRest(arrayToList(local.hashes))));
			}
			local.empty = [];
			return local.empty;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="_generateStrongPassword" output="false"
	            hint="Generate a strong password that is not similar to the specified old password.">
		<cfargument required="true" type="String" name="oldPassword" hint="the password to be compared to the new password for similarity"/>

		<cfset var local = {}/>

		<cfscript>
			local.r = instance.ESAPI.randomizer();
			local.letters = local.r.getRandomInteger(4, 6);// inclusive, exclusive
			local.digits = 7 - local.letters;
			local.passLetters = local.r.getRandomString(local.letters, newJava("org.owasp.esapi.EncoderConstants").CHAR_PASSWORD_LETTERS);
			local.passDigits = local.r.getRandomString(local.digits, newJava("org.owasp.esapi.EncoderConstants").CHAR_PASSWORD_DIGITS);
			local.passSpecial = local.r.getRandomString(1, newJava("org.owasp.esapi.EncoderConstants").CHAR_PASSWORD_SPECIALS);
			local.newPassword = local.passLetters & local.passSpecial & local.passDigits;
			if(newJava("org.owasp.esapi.StringUtilities").getLevenshteinDistance(arguments.oldPassword, local.newPassword) > 5) {
				return local.newPassword;
			}
			return _generateStrongPassword(arguments.oldPassword);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="currentPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>
		<cfargument required="true" type="String" name="newPassword2"/>

		<cfset var local = {}/>

		<cfscript>
			local.accountName = arguments.user.getAccountName();
			try {
				local.currentHash = getHashedPassword(arguments.user);
				local.verifyHash = hashPassword(arguments.currentPassword, local.accountName);
				if(!local.currentHash.equals(local.verifyHash)) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Authentication failed for password change on user: " & local.accountName);
					throwError(local.exception);
				}
				if(arguments.newPassword == "" || arguments.newPassword2 == "" || !arguments.newPassword.equals(arguments.newPassword2)) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Passwords do not match for password change on user: " & local.accountName);
					throwError(local.exception);
				}
				verifyPasswordStrength(arguments.currentPassword, arguments.newPassword, arguments.user);
				arguments.user.setLastPasswordChangeTime(newJava("java.util.Date").init());
				local.newHash = hashPassword(arguments.newPassword, local.accountName);
				if(arrayFind(getOldPasswordHashes(arguments.user), local.newHash)) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Password change failed", "Password change matches a recent password for user: " & local.accountName);
					throwError(local.exception);
				}
				setHashedPassword(arguments.user, local.newHash);
				instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Password changed for user: " & local.accountName);
				// jtm - 11/2/2010 - added to resolve http://code.google.com/p/owasp-esapi-java/issues/detail?id=13
				saveUsers();
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException ee) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationException").init(instance.ESAPI, "Password change failed", "Encryption exception changing password for " & local.accountName, ee);
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument required="true" type="String" name="password"/>

		<cfset var local = {}/>

		<cfscript>
			local.accountName = arguments.user.getAccountName();
			try {
				local.hash = hashPassword(arguments.password, local.accountName);
				local.currentHash = getHashedPassword(arguments.user);
				if(local.hash.equals(local.currentHash)) {
					arguments.user.setLastLoginTime(newJava("java.util.Date").init());
					arguments.user.setFailedLoginCount(0);
					instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Password verified for " & local.accountName);
					return true;
				}
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Encryption error verifying password for " & local.accountName);
			}
			instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Password verification failed for " & local.accountName);
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user"/>
		<cfargument type="String" name="oldPassword"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "user") && structKeyExists(arguments, "oldPassword")) {
				local.newPassword = _generateStrongPassword(arguments.oldPassword);
				if(structKeyExists(local, "newPassword")) {
					instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Generated strong password for " & arguments.user.getAccountName());
				}
				return local.newPassword;
			}
			else {
				return _generateStrongPassword("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountId" output="false">
		<cfargument required="true" type="numeric" name="accountId"/>

		<cfscript>
			if(arguments.accountId == 0) {
				return newComponent("cfesapi.org.owasp.esapi.User$ANONYMOUS").init(instanceESAPI);
			}
			loadUsersIfNecessary();
			if(structKeyExists(instance.userMap, arguments.accountId)) {
				return instance.userMap.get(arguments.accountId);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserByAccountName" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.accountName == "") {
				return newComponent("cfesapi.org.owasp.esapi.User$ANONYMOUS").init(instanceESAPI);
			}
			loadUsersIfNecessary();
			for(local.u in instance.userMap) {
				if(instance.userMap[local.u].getAccountName().equalsIgnoreCase(arguments.accountName)) {
					return instance.userMap[local.u];
				}
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getUserNames" output="false">
		<cfset var local = {}/>

		<cfscript>
			loadUsersIfNecessary();
			local.results = [];
			for(local.u in instance.userMap) {
				local.results.add(instance.userMap[local.u].getAccountName());
			}
			return local.results;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="hashPassword" output="false">
		<cfargument required="true" type="String" name="password"/>
		<cfargument required="true" type="String" name="accountName"/>

		<cfset var local = {}/>

		<cfscript>
			local.salt = arguments.accountName.toLowerCase();
			return instance.ESAPI.encryptor().hashESAPI(arguments.password, local.salt);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeUser" output="false">
		<cfargument required="true" type="String" name="accountName"/>

		<cfset var local = {}/>

		<cfscript>
			loadUsersIfNecessary();
			local.user = getUserByAccountName(arguments.accountName);
			if(!isObject(local.user)) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException").init(instance.ESAPI, "Remove user failed", "Can't remove invalid accountName " & arguments.accountName);
				throwError(local.exception);
			}
			instance.userMap.remove(local.user.getAccountId());
			instance.logger.info(newJava("org.owasp.esapi.Logger").SECURITY_SUCCESS, "Removing user " & local.user.getAccountName());
			instance.passwordMap.remove(local.user.getAccountId());
			saveUsers();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false"
	            hint="This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a brute force attack, however the real strength comes from the name length and complexity.">
		<cfargument required="true" type="String" name="accountName"/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.accountName == "") {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "Attempt to create account with a null account name");
				throwError(local.exception);
			}
			if(!instance.ESAPI.validator().isValidInput("verifyAccountNameStrength", arguments.accountName, "AccountName", instance.MAX_ACCOUNT_NAME_LENGTH, false)) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid account name", "New account name is not valid: " & arguments.accountName);
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false"
	            hint="This implementation checks: - for any 3 character substrings of the old password - for use of a length * character sets > 16 (where character sets are upper, lower, digit, and special; check to verify pw != username">
		<cfargument type="String" name="oldPassword"/>
		<cfargument required="true" type="String" name="newPassword"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user"/>

		<cfset var local = {}/>

		<cfscript>
			if(!structKeyExists(arguments, "newPassword")) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password cannot be null");
				throwError(local.exception);
			}

			// can't change to a password that contains any 3 character substring of old password
			if(structKeyExists(arguments, "oldPassword")) {
				local.length = arguments.oldPassword.length();
				for(local.i = 0; local.i < local.length - 2; local.i++) {
					local.sub = arguments.oldPassword.substring(local.i, local.i + 3);
					if(arguments.newPassword.indexOf(local.sub) > -1) {
						local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password cannot contain pieces of old password");
						throwError(local.exception);
					}
				}
			}

			// new password must have enough character sets and length
			local.charsets = 0;
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
				if(newJava("java.util.Arrays").binarySearch(newJava("org.owasp.esapi.EncoderConstants").CHAR_LOWERS, arguments.newPassword.charAt(local.i)) >= 0) {
					local.charsets++;
					break;
				}
			}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
				if(newJava("java.util.Arrays").binarySearch(newJava("org.owasp.esapi.EncoderConstants").CHAR_UPPERS, arguments.newPassword.charAt(local.i)) >= 0) {
					local.charsets++;
					break;
				}
			}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
				if(newJava("java.util.Arrays").binarySearch(newJava("org.owasp.esapi.EncoderConstants").CHAR_DIGITS, arguments.newPassword.charAt(local.i)) >= 0) {
					local.charsets++;
					break;
				}
			}
			for(local.i = 0; local.i < arguments.newPassword.length(); local.i++) {
				if(newJava("java.util.Arrays").binarySearch(newJava("org.owasp.esapi.EncoderConstants").CHAR_SPECIALS, arguments.newPassword.charAt(local.i)) >= 0) {
					local.charsets++;
					break;
				}
			}

			// calculate and verify password strength
			local.strength = arguments.newPassword.length() * local.charsets;
			if(local.strength < 16) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "New password is not long and complex enough");
				throwError(local.exception);
			}

			local.accountName = arguments.user.getAccountName();

			//jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
			if(local.accountName.equalsIgnoreCase(arguments.newPassword)) {
				//password can't be account name
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException").init(instance.ESAPI, "Invalid password", "Password matches account name, irrespective of case");
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

</cfcomponent>