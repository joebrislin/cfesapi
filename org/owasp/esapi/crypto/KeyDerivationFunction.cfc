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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
		this.kdfVersion = 20110203;// Format: YYYYMMDD, max is 99991231.
		instance.serialVersionUID = this.kdfVersion;// Format: YYYYMMDD
		instance.ESAPI = "";
		instance.logger = "";

		instance.prfAlg_ = "";
		instance.version_ = this.kdfVersion;
		instance.context_ = "";

		// Pseudo-random function algorithms suitable for NIST KDF in counter mode.
		// Note that HmacMD5 is intentionally omitted here!!!
		instance.PRF_ALGORITHMS = {HmacSHA1=newComponent("cfesapi.org.owasp.esapi.crypto.PRF_ALGORITHMS").init(0, 160, "HmacSHA1"), HmacSHA256=newComponent("cfesapi.org.owasp.esapi.crypto.PRF_ALGORITHMS").init(1, 256, "HmacSHA256"), HmacSHA384=newComponent("cfesapi.org.owasp.esapi.crypto.PRF_ALGORITHMS").init(2, 384, "HmacSHA384"), HmacSHA512=newComponent("cfesapi.org.owasp.esapi.crypto.PRF_ALGORITHMS").init(3, 512, "HmacSHA512")};
	</cfscript>

	<cffunction access="public" returntype="KeyDerivationFunction" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>
		<cfargument type="PRF_ALGORITHMS" name="prfAlg" required="false"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("KeyDerivationFunction");

			if(structKeyExists(arguments, "prfAlg")) {
				instance.prfAlg_ = arguments.prfAlg.getAlgName();
			}
			else {
				local.prfName = instance.ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
				if(!isValidPRF(local.prfName)) {
					throwError(newComponent("ConfigurationException").init("Algorithm name " & local.prfName & " not a valid algorithm name for property " & DefaultSecurityConfiguration.KDF_PRF_ALG));
				}
				instance.prfAlg_ = local.prfName;
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPRFAlgName" output="false"
	            hint="Return the name of the algorithm for the Pseudo Random Function (PRF) that is being used.">

		<cfscript>
			return instance.prfAlg_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getDefaultPRFSelection" output="false"
	            hint="Package level method for use by CipherText class to get default">
		<cfset var local = {}/>

		<cfscript>
			local.prfName = instance.ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
			for(local.prf in instance.PRF_ALGORITHMS) {
				if(instance.PRF_ALGORITHMS[local.prf].getAlgName() == local.prfName) {
					return instance.PRF_ALGORITHMS[local.prf].getValue();
				}
			}
			throwError(newComponent("ConfigurationException").init("Algorithm name " & local.prfName & " not a valid algorithm name for property " & DefaultSecurityConfiguration.KDF_PRF_ALG));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setVersion" output="false"
	            hint="Set version so backward compatibility can be supported. Used to set the version to some previous version so that previously encrypted data can be decrypted.">
		<cfargument type="numeric" name="version" required="true" hint="Date as a integer, in format of YYYYMMDD. Maximum version date is 99991231 (December 31, 9999)."/>

		<cfscript>
			if(arguments.version < 0 || arguments.version > 99991231) {
				throwError(newJava("IllegalArgumentException").init("Version (" & arguments.version & ") invalid. Must be date in format of YYYYMMDD < 99991231."));
			}
			instance.version_ = arguments.version;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getVersion" output="false"
	            hint="Return the version used for backward compatibility.">

		<cfscript>
			return instance.version_;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContext" output="false"
	            hint="Set the 'context' as specified by NIST Special Publication 800-108.">
		<cfargument type="String" name="context" required="true" hint="Optional binary string containing information related to the derived keying material. By default (if this method is never called), the empty string is used. May have any value but null."/>

		<cfscript>
			assert(structKeyExists(arguments, "context"), "Context may not be null.");
			instance.context_ = arguments.context;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContext" output="false"
	            hint="Return the optional 'context' that typically contains information related to the keying material, such as the identities of the message sender and recipient.">

		<cfscript>
			return instance.context_;
		</cfscript>

	</cffunction>

	<!--- computeDerivedKey --->

	<cffunction access="public" returntype="boolean" name="isValidPRF" output="false"
	            hint="Check if specified algorithm name is a valid PRF that can be used.">
		<cfargument type="String" name="prfAlgName" required="true" hint="Name of the PRF algorithm; e.g., 'HmacSHA1', 'HmacSHA384', etc."/>

		<cfset var local = {}/>

		<cfscript>
			for(local.prf in instance.PRF_ALGORITHMS) {
				if(instance.PRF_ALGORITHMS[local.prf].getAlgName() == arguments.prfAlgName) {
					return true;
				}
			}
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="PRF_ALGORITHMS" name="convertNameToPRF" output="false">
		<cfargument type="String" name="prfAlgName" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			for(local.prf in instance.PRF_ALGORITHMS) {
				if(instance.PRF_ALGORITHMS[local.prf].getAlgName() == arguments.prfAlgName) {
					return instance.PRF_ALGORITHMS[local.prf];
				}
			}
			throwError(newJava("IllegalArgumentException").init("Algorithm name " & arguments.prfAlgName & " not a valid PRF algorithm name for the ESAPI KDF."));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="PRF_ALGORITHMS" name="convertIntToPRF" output="false">
		<cfargument type="numeric" name="selection" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			for(local.prf in instance.PRF_ALGORITHMS) {
				if(instance.PRF_ALGORITHMS[local.prf].getValue() == arguments.selection) {
					return instance.PRF_ALGORITHMS[local.prf];
				}
			}
			throwError(newJava("IllegalArgumentException").init("No KDF PRF algorithm found for value name " & arguments.selection));
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="numeric" name="calcKeySize" output="false"
	            hint="Calculate the size of a key. The key size is given in bits, but we can only allocate them by octets (i.e., bytes), so make sure we round up to the next whole number of octets to have room for all the bits. For example, a key size of 9 bits would require 2 octets to store it.">
		<cfargument type="numric" name="ks" required="true" hint="The key size, in bits."/>

		<cfset var local = {}/>

		<cfscript>
			assert(arguments.ks > 0, "Key size must be > 0 bits.");
			local.numBytes = 0;
			local.n = arguments.ks / 8;
			local.rem = arguments.ks % 8;
			if(local.rem == 0) {
				local.numBytes = local.n;
			}
			else {
				local.numBytes = local.n + 1;
			}
			return local.numBytes;
		</cfscript>

	</cffunction>

</cfcomponent>