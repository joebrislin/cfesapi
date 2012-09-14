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
<cfcomponent displayname="DefaultValidator" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Validator" output="false"
             hint="Reference implementation of the Validator interface. This implementation relies on the ESAPI Encoder, Java Pattern (regex), Date, and several other classes to provide basic validation functions. This library has a heavy emphasis on whitelist validation and canonicalization.">

	<cfscript>
		instance.ESAPI = "";

		/* A map of validation rules */
		instance.rules = {};

		/* The encoder to use for canonicalization */
		instance.encoder = "";

		/* The encoder to use for file system */
		instance.fileValidator = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Validator" name="init" output="false"
	            hint="Construct a new DefaultValidator that will use the specified Encoder for canonicalization.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder"/>
		<cfargument type="boolean" name="nested" default="false"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			if(structKeyExists(arguments, "encoder")) {
				instance.encoder = arguments.encoder;
			}
			else {
				instance.encoder = instance.ESAPI.encoder();
			}

			// FIXME: are we able to identify the caller to determine whether this is nested rather than passing a stupid argument ???
			if(!arguments.nested) {
				/* Initialize file validator with an appropriate set of codecs */
				local.list = [];
				local.list.add("HTMLEntityCodec");
				local.list.add("PercentCodec");
				local.fileEncoder = newComponent("cfesapi.org.owasp.esapi.reference.DefaultEncoder").init(instance.ESAPI, local.list);
				instance.fileValidator = newComponent("cfesapi.org.owasp.esapi.reference.DefaultValidator").init(instance.ESAPI, local.fileEncoder, true);// this is only call where nested arg will be true
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addRule" output="false"
	            hint="Add a validation rule to the registry using the 'type name' of the rule as the key.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ValidationRule" name="rule"/>

		<cfscript>
			instance.rules[arguments.rule.getTypeName()] = arguments.rule;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.ValidationRule" name="getRule" output="false"
	            hint="Get a validation rule from the registry with the 'type name' of the rule as the key.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			if(structKeyExists(instance.rules, arguments.name)) {
				return instance.rules[arguments.name];
			}
			return newComponent("cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidInput" output="false"
	            hint="Returns true if data received from browser is valid. Double encoding is treated as an attack. The default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized by default before validation.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name for the field to validate. This is used for error facing validation messages and element identification."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name while maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="boolean" name="canonicalize" default="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidInput" output="false"
	            hint="Validates data received from the browser and returns a safe version. Double encoding is treated as an attack. The default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized by default before validation.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name for the field to validate. This is used for error facing validation messages and element identification."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name which maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="boolean" name="canonicalize" default="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return "";
			}

			local.rvr = newComponent("cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, arguments.type, instance.encoder);
			local.p = instance.ESAPI.securityConfiguration().getValidationPattern(arguments.type);
			if(structKeyExists(local, "p")) {
				local.rvr.addWhitelistPattern(local.p);
			}
			else {
				// Issue 232 - Specify requested type in exception message - CS
				throwError(newJava("java.lang.IllegalArgumentException").init("The selected type [" & arguments.type & "] was not set via the ESAPI validation configuration"));
			}
			local.rvr.setMaximumLength(arguments.maxLength);
			local.rvr.setAllowNull(arguments.allowNull);
			local.rvr.setValidateInputAndCanonical(arguments.canonicalize);
			
			return local.rvr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDate" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDate" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return null
				return "";
			}

			local.dvr = newComponent("cfesapi.org.owasp.esapi.reference.validation.DateValidationRule").init(instance.ESAPI, "SimpleDate", instance.encoder, arguments.format);
			local.dvr.setAllowNull(arguments.allowNull);
			return local.dvr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidSafeHTML" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidSafeHTML" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.hvr = newComponent("cfesapi.org.owasp.esapi.reference.validation.HTMLValidationRule").init(instance.ESAPI, "safehtml", instance.encoder);
			local.hvr.setMaximumLength(arguments.maxLength);
			local.hvr.setAllowNull(arguments.allowNull);
			local.hvr.setValidateInputAndCanonical(false);
			return local.hvr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidCreditCard" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.ccvr = newComponent("cfesapi.org.owasp.esapi.reference.validation.CreditCardValidationRule").init(instance.ESAPI, "creditcard", instance.encoder);
			local.ccvr.setAllowNull(arguments.allowNull);
			return local.ccvr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDirectoryPath" output="false"
	            hint="Note: On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real path (/private/etc), not the symlink (/etc).">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="parent"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidDirectoryPath(arguments.context, arguments.input, arguments.parent, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="parent"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDirectoryPath(arguments.context, arguments.input, arguments.parent, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			try {
				if(isEmpty(arguments.input)) {
					if(arguments.allowNull)
						return "";
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input directory path required", logMessage="Input directory path required context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
				}

				local.dir = newJava("java.io.File").init(arguments.input);

				// check dir exists and parent exists and dir is inside parent
				if(!local.dir.exists()) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input));
				}
				if(!local.dir.isDirectory()) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input));
				}
				if(!arguments.parent.exists()) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent));
				}
				if(!arguments.parent.isDirectory()) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent));
				}
				if(!local.dir.getCanonicalPath().startsWith(arguments.parent.getCanonicalPath())) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not inside specified parent: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent));
				}

				// check canonical form matches input
				local.canonicalPath = local.dir.getCanonicalPath();
				local.canonical = instance.fileValidator.getValidInput(arguments.context, local.canonicalPath, "DirectoryName", 255, false);
				if(!local.canonical.equals(arguments.input)) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid directory name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context));
				}
				return local.canonical;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileName" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument type="Array" name="allowedExtensions" default="#instance.ESAPI.securityConfiguration().getAllowedFileExtensions()#"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidFileName(arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidFileName" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="allowedExtensions"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileName(arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			if(arguments.allowedExtensions.isEmpty()) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded"));
			}

			local.canonical = "";
			// detect path manipulation
			try {
				if(isEmpty(arguments.input)) {
					if(arguments.allowNull)
						return "";
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input file name required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
				}

				// do basic validation
				local.canonical = newJava("java.io.File").init(arguments.input).getCanonicalFile().getName();
				getValidInput(arguments.context, arguments.input, "FileName", 255, true);

				local.f = newJava("java.io.File").init(local.canonical);
				local.c = local.f.getCanonicalPath();
				local.cpath = local.c.substring(local.c.lastIndexOf(newJava("java.io.File").separator) + 1);

				// the path is valid if the input matches the canonical path
				if(arguments.input != local.cpath) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context));
				}
			}
			catch(java.io.IOException e) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & local.canonical, e, arguments.context));
			}

			// verify extensions
			local.i = arguments.allowedExtensions.iterator();
			while(local.i.hasNext()) {
				local.ext = local.i.next();
				if(arguments.input.toLowerCase().endsWith(local.ext.toLowerCase())) {
					return local.canonical;
				}
			}
			throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & ")", logMessage="Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & "): context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidNumber" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return "";
			}

			local.minDoubleValue = newJava("java.lang.Double").init(arguments.minValue);
			local.maxDoubleValue = newJava("java.lang.Double").init(arguments.maxValue);
			return getValidDouble(arguments.context, arguments.input, local.minDoubleValue.doubleValue(), local.maxDoubleValue.doubleValue(), arguments.allowNull);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDouble" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDouble" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				return newJava("java.lang.Double").init(newJava("java.lang.Double").NaN);
			}

			local.nvr = newComponent("cfesapi.org.owasp.esapi.reference.validation.NumberValidationRule").init(instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue);
			local.nvr.setAllowNull(arguments.allowNull);
			return local.nvr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidInteger" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidInteger" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return "";
			}

			local.ivr = newComponent("cfesapi.org.owasp.esapi.reference.validation.IntegerValidationRule").init(instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue);
			local.ivr.setAllowNull(arguments.allowNull);
			return local.ivr.getValid(arguments.context, arguments.input);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileContent" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="getValidFileContent" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// return empty byte array on error
				return newJava("java.lang.String").init("").getBytes();
			}

			if(isEmpty(arguments.input)) {
				if(arguments.allowNull)
					return "";
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
			}

			local.esapiMaxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();
			if(len(arguments.input) > local.esapiMaxBytes) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & local.esapiMaxBytes & " bytes", logMessage="Exceeded ESAPI max length", context=arguments.context));
			}
			if(len(arguments.input) > arguments.maxBytes) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", logMessage="Exceeded maxBytes ( " & len(arguments.input) & ")", context=arguments.context));
			}

			return arguments.input;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileUpload" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="filepath"/>
		<cfargument required="true" type="String" name="filename"/>
		<cfargument required="true" name="parent"/>
		<cfargument required="true" type="binary" name="content"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				return (isValidFileName(context=arguments.context, input=arguments.filename, allowNull=arguments.allowNull, errorList=arguments.errorList) && isValidDirectoryPath(arguments.context, arguments.filepath, arguments.parent, arguments.allowNull, arguments.errorList) && isValidFileContent(arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull, arguments.errorList));
			}
			else {
				return (isValidFileName(context=arguments.context, input=arguments.filename, allowNull=arguments.allowNull) && isValidDirectoryPath(arguments.context, arguments.filepath, arguments.parent, arguments.allowNull) && isValidFileContent(arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValidFileUpload" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="filepath"/>
		<cfargument required="true" type="String" name="filename"/>
		<cfargument required="true" name="parent"/>
		<cfargument required="true" type="binary" name="content"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="Array" name="allowedExtensions"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					assertValidFileUpload(arguments.context, arguments.filepath, arguments.filename, arguments.parent, arguments.content, arguments.maxBytes, arguments.allowedExtensions, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
			}
			else {
				getValidFileName(arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull);
				getValidDirectoryPath(arguments.context, arguments.filepath, arguments.parent, arguments.allowNull);
				getValidFileContent(arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidListItem" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="list"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidListItem(arguments.context, arguments.input, arguments.list);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidListItem" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="list"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidListItem(arguments.context, arguments.input, arguments.list);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return arguments.input;
			}

			if(arguments.list.contains(arguments.input))
				return arguments.input;
			throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid list item", logMessage="Invalid list item: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequestParameterSet" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="Array" name="requiredNames"/>
		<cfargument required="true" type="Array" name="optionalNames"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				assertValidHTTPRequestParameterSet(arguments.context, arguments.request, arguments.requiredNames, arguments.optionalNames);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValidHTTPRequestParameterSet" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="Array" name="requiredNames"/>
		<cfargument required="true" type="Array" name="optionalNames"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					assertValidHTTPRequestParameterSet(arguments.context, arguments.request, arguments.requiredNames, arguments.optionalNames);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
			}

			local.actualNames = arguments.request.getParameterMap().keySet();

			// verify ALL required parameters are present
			local.missing = duplicate(arguments.requiredNames);
			local.missing.removeAll(local.actualNames);
			if(local.missing.size() > 0) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request missing parameters", logMessage="Invalid HTTP request missing parameters " & arrayToList(local.missing) & ": context=" & arguments.context, context=arguments.context));
			}

			// verify ONLY optional + required parameters are present
			local.extra = duplicate(local.actualNames);
			local.extra.removeAll(arguments.requiredNames);
			local.extra.removeAll(arguments.optionalNames);
			if(local.extra.size() > 0) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request extra parameters " & local.extra, logMessage="Invalid HTTP request extra parameters " & local.extra & ": context=" & arguments.context, context=arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidPrintable" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				if(structKeyExists(arguments, "errorList")) {
					arguments.errorList.addError(arguments.context, e);
				}
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidPrintable" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				// error has been added to list, so return original input
				return arguments.input;
			}

			if(isSimpleValue(arguments.input)) {
				try {
					local.canonical = instance.encoder.canonicalize(arguments.input);
					return newJava("java.lang.String").init(getValidPrintable(arguments.context, local.canonical.toCharArray(), arguments.maxLength, arguments.allowNull));
					//TODO - changed this to base Exception since we no longer need EncodingException
					//TODO - this is a bit lame: we need to re-think this function.
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, arguments.context & ": Invalid printable input", "Invalid encoding of printable input, context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
				}
			}
			else if(isArray(arguments.input)) {
				if(isEmpty(arguments.input)) {
					if(arguments.allowNull)
						return "";
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes required", logMessage="Input bytes required: HTTP request is null", context=arguments.context));
				}

				if(arrayLen(arguments.input) > arguments.maxLength) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (arguments.input.length - arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context));
				}

				for(local.i = 1; local.i <= arrayLen(arguments.input); local.i++) {
					local.input = arguments.input[local.i];
					if(!isNumeric(local.input)) {
						local.input = asc(local.input);
					}
					if(local.input <= inputBaseN("20", 16) || local.input >= inputBaseN("7E", 16)) {
						throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input bytes: context=" & arguments.context, logMessage="Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context));
					}
				}
				return arguments.input;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidRedirectLocation" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				return instance.ESAPI.validator().isValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull, arguments.errorList);
			}
			else {
				return instance.ESAPI.validator().isValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidRedirectLocation" output="false">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			try {
				return instance.ESAPI.validator().getValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return original input
			return arguments.input;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="safeReadLine" output="false"
	            hint="This implementation reads until a newline or the specified number of characters.">
		<cfargument required="true" name="inputStream"/>
		<cfargument required="true" type="numeric" name="maxLength"/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.maxLength <= 0) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream"));
			}

			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.count = 0;

			try {
				while(true) {
					local.c = arguments.inputStream.read();
					if(local.c == -1) {
						if(local.sb.length() == 0) {
							return;
						}
						break;
					}
					if(local.c == 13 || local.c == 10) {
						break;
					}
					local.count++;
					if(local.count > arguments.maxLength) {
						throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.maxLength & ")"));
					}
					local.sb.append(chr(local.c));
				}
				return local.sb.toStringESAPI();
			}
			catch(java.lang.IOException e) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException").init(instance.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="isEmpty" output="false"
	            hint="Helper function to check if a variable is empty">
		<cfargument required="true" name="input" hint="input value"/>

		<cfscript>
			if(isSimpleValue(arguments.input)) {
				return (arguments.input == "" || arguments.input.trim().length() == 0);
			}
			else if(isBinary(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
			else if(isArray(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
		</cfscript>

	</cffunction>

</cfcomponent>