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
		this.cipherTextSerializerVersion = 20110203;// Format: YYYYMMDD, max is 99991231.
		instance.serialVersionUID = this.cipherTextSerializerVersion;

		CryptoHelper = "";

		instance.ESAPI = "";
		instance.logger = "";
		instance.cipherText_ = "";
	</cfscript>

	<cffunction access="public" returntype="CipherTextSerializer" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherText" name="cipherTextObj" required="false"/>
		<cfargument type="binary" name="cipherTextSerializedBytes" required="false" hint="A serialized CipherText object with the bytes in network byte order."/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("CipherTextSerializer");

			CryptoHelper = newComponent("cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);
			CipherText = newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI);

			if(structKeyExists(arguments, "cipherTextObj")) {
				assert(structKeyExists(arguments, "cipherTextObj"), "CipherText object must not be null.");
				assert(instance.serialVersionUID == CipherText.getSerialVersionUID(), "Version of CipherText and CipherTextSerializer not compatible.");
				instance.cipherText_ = arguments.cipherTextObj;
			}
			else if(structKeyExists(arguments, "cipherTextSerializedBytes")) {
				assert(instance.serialVersionUID == CipherText.getSerialVersionUID(), "Version of CipherText and CipherTextSerializer not compatible.");
				instance.cipherText_ = convertToCipherText(arguments.cipherTextSerializedBytes);
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="asSerializedByteArray" output="false"
	            hint="Return this CipherText object as a specialized, portable serialized byte array (binary).">
		<cfset var local = {}/>

		<cfscript>
			local.vers = instance.cipherText_.getSerialVersionUID();// static method
			local.timestamp = instance.cipherText_.getEncryptionTimestamp();
			local.cipherXform = instance.cipherText_.getCipherTransformation();
			assert(instance.cipherText_.getKeySize() < newJava("java.lang.Short").MAX_VALUE, "Key size too large. Max is " & newJava("java.lang.Short").MAX_VALUE);
			local.keySize = instance.cipherText_.getKeySize();
			assert(instance.cipherText_.getBlockSize() < newJava("java.lang.Short").MAX_VALUE, "Block size too large. Max is " & newJava("java.lang.Short").MAX_VALUE);
			local.blockSize = instance.cipherText_.getBlockSize();
			local.iv = instance.cipherText_.getIV();
			assert(arrayLen(local.iv) < newJava("java.lang.Short").MAX_VALUE, "IV size too large. Max is " & newJava("java.lang.Short").MAX_VALUE);
			local.ivLen = arrayLen(local.iv);
			local.rawCiphertext = instance.cipherText_.getRawCipherText();
			local.ciphertextLen = arrayLen(local.rawCiphertext);
			assert(local.ciphertextLen >= 1, "Raw ciphertext length must be >= 1 byte.");
			local.mac = instance.cipherText_.getSeparateMAC();
			assert(arrayLen(local.mac) < newJava("java.lang.Short").MAX_VALUE, "MAC length too large. Max is " & newJava("java.lang.Short").MAX_VALUE);
			local.macLen = arrayLen(local.mac);

			local.serializedObj = computeSerialization(local.vers, local.timestamp, local.cipherXform, local.keySize, local.blockSize, local.ivLen, local.iv, local.ciphertextLen, local.rawCiphertext, local.macLen, local.mac);

			return local.serializedObj;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="CipherText" name="asCipherText" output="false">

		<cfscript>
			return instance.cipherText_;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="binary" name="computeSerialization" output="false">
		<cfargument type="numeric" name="vers" required="true"/>
		<cfargument type="numeric" name="timestamp" required="true"/>
		<cfargument type="String" name="cipherXform" required="true"/>
		<cfargument type="numeric" name="keySize" required="true"/>
		<cfargument type="numeric" name="blockSize" required="true"/>
		<cfargument type="numeric" name="ivLen" required="true"/>
		<cfargument type="binary" name="iv" required="true"/>
		<cfargument type="numeric" name="ciphertextLen" required="true"/>
		<cfargument type="binary" name="rawCiphertext" required="true"/>
		<cfargument type="numeric" name="macLen" required="true"/>
		<cfargument type="binary" name="mac" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			debug("computeSerialization: vers = " & arguments.vers);
			debug("computeSerialization: timestamp = " & newJava("java.util.Date").init(javaCast("long", arguments.timestamp)));
			debug("computeSerialization: cipherXform = " & arguments.cipherXform);
			debug("computeSerialization: keySize = " & arguments.keySize);
			debug("computeSerialization: blockSize = " & arguments.blockSize);
			debug("computeSerialization: ivLen = " & arguments.ivLen);
			debug("computeSerialization: ciphertextLen = " & arguments.ciphertextLen);
			debug("computeSerialization: macLen = " & arguments.macLen);

			local.baos = newJava("java.io.ByteArrayOutputStream").init();
			writeLong(local.baos, arguments.vers);
			writeLong(local.baos, arguments.timestamp);
			local.parts = arguments.cipherXform.split("/");
			assert(arrayLen(local.parts) == 3, "Malformed cipher transformation");
			writeString(local.baos, arguments.cipherXform);// Size of string is prepended to string
			writeShort(local.baos, arguments.keySize);
			writeShort(local.baos, arguments.blockSize);
			writeShort(local.baos, arguments.ivLen);
			if(arguments.ivLen > 0)
				local.baos.write(arguments.iv, 0, arrayLen(arguments.iv));
			writeInt(local.baos, arguments.ciphertextLen);
			local.baos.write(arguments.rawCiphertext, 0, arrayLen(arguments.rawCiphertext));
			writeShort(local.baos, arguments.macLen);
			if(arguments.macLen > 0)
				local.baos.write(arguments.mac, 0, arrayLen(arguments.mac));
			return local.baos.toByteArray();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="writeString" output="false"
	            hint="All strings are written as UTF-8 encoded byte streams with the length prepended before it as a short.">
		<cfargument type="any" name="baos" required="true" hint="java.io.ByteArrayOutputStream"/>
		<cfargument type="String" name="str" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				assert(structKeyExists(arguments, "str") && arguments.str.length() > 0);
				local.bytes = arguments.str.getBytes("UTF8");
				assert(arrayLen(local.bytes) < newJava("java.lang.Short").MAX_VALUE, "writeString: String exceeds max length");
				writeShort(arguments.baos, arrayLen(local.bytes));
				arguments.baos.write(local.bytes, 0, arrayLen(local.bytes));
			}
			catch(java.io.UnsupportedEncodingException e) {
				// Should never happen. UTF8 is built into the rt.jar. We don't use native encoding as
				// a fall-back because that simply is not guaranteed to be portable across Java
				// platforms and could cause really bizarre errors way downstream.
				instance.logger.error(newJava("org.owasp.esapi.Logger").EVENT_FAILURE, "Ignoring caught UnsupportedEncodingException converting string to UTF8 encoding. Results suspect. Corrupt rt.jar????");
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="readString" output="false">
		<cfargument type="any" name="bais" required="true" hint="java.io.ByteArrayInputStream"/>
		<cfargument type="numeric" name="sz" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.bytes = newByte(arguments.sz);
			local.ret = arguments.bais.read(local.bytes, 0, arguments.sz);
			assert(local.ret == arguments.sz, "readString: Failed to read " & arguments.sz & " bytes.");
			return newJava("java.lang.String").init(local.bytes, "UTF8");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="writeShort" output="false">
		<cfargument type="any" name="baos" required="true" hint="java.io.ByteArrayOutputStream"/>
		<cfargument type="numeric" name="s" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.shortAsByteArray = newJava("org.owasp.esapi.util.ByteConversionUtil").fromShort(arguments.s);
			assert(arrayLen(local.shortAsByteArray) == 2);
			baos.write(local.shortAsByteArray, 0, 2);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="numeric" name="readShort" output="false">
		<cfargument type="any" name="bais" required="true" hint="java.io.ByteArrayInputStream"/>

		<cfset var local = {}/>

		<cfscript>
			local.shortAsByteArray = newByte(2);
			local.ret = arguments.bais.read(local.shortAsByteArray, 0, 2);
			assert(local.ret == 2, "readShort: Failed to read 2 bytes.");
			return newJava("org.owasp.esapi.util.ByteConversionUtil").toShort(local.shortAsByteArray);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="writeInt" output="false">
		<cfargument type="any" name="baos" required="true" hint="java.io.ByteArrayOutputStream"/>
		<cfargument type="numeric" name="i" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.intAsByteArray = newJava("org.owasp.esapi.util.ByteConversionUtil").fromInt(arguments.i);
			baos.write(local.intAsByteArray, 0, 4);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="numeric" name="readInt" output="false">
		<cfargument type="any" name="bais" required="true" hint="java.io.ByteArrayInputStream"/>

		<cfset var local = {}/>

		<cfscript>
			local.intAsByteArray = newByte(4);
			local.ret = arguments.bais.read(local.intAsByteArray, 0, 4);
			assert(local.ret == 4, "readInt: Failed to read 4 bytes.");
			return newJava("org.owasp.esapi.util.ByteConversionUtil").toInt(local.intAsByteArray);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="writeLong" output="false">
		<cfargument type="any" name="baos" required="true" hint="java.io.ByteArrayOutputStream"/>
		<cfargument type="numeric" name="l" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.longAsByteArray = newJava("org.owasp.esapi.util.ByteConversionUtil").fromLong(arguments.l);
			assert(arrayLen(local.longAsByteArray) == 8);
			baos.write(local.longAsByteArray, 0, 8);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="numeric" name="readLong" output="false">
		<cfargument type="any" name="bais" required="true" hint="java.io.ByteArrayInputStream"/>

		<cfset var local = {}/>

		<cfscript>
			local.longAsByteArray = newByte(8);
			local.ret = arguments.bais.read(local.longAsByteArray, 0, 8);
			assert(local.ret == 8, "readLong: Failed to read 8 bytes.");
			return newJava("org.owasp.esapi.util.ByteConversionUtil").toLong(local.longAsByteArray);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="CipherText" name="convertToCipherText" output="false">
		<cfargument type="binary" name="cipherTextSerializedBytes" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				local.bais = newJava("java.io.ByteArrayInputStream").init(arguments.cipherTextSerializedBytes);
				local.vers = readLong(local.bais);
				debug("convertToCipherText: vers = " & local.vers);
				local.svUID = newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).getSerialVersionUID();
				/* TODO: valid objects are being tripped up here
				if ( local.vers != local.svUID ) {
				    // NOTE: In future, support backward compatibility via this mechanism. As of now,
				    //       this is first version so nothing to be backward compatible with. So any
				    //       mismatch at this point is an error.
				    throwError(newJava("java.io.InvalidClassException").init("This serialized byte stream not compatible with loaded CipherText class. Version read = " & local.vers & "; version from loaded CipherText class = " & local.svUID)));
				}*/
				local.timestamp = readLong(local.bais);
				debug("convertToCipherText: timestamp = " & newJava("java.util.Date").init(javaCast("long", local.timestamp)));
				local.strSize = readShort(local.bais);
				debug("convertToCipherText: length of cipherXform = " & local.strSize);
				local.cipherXform = readString(local.bais, local.strSize);
				debug("convertToCipherText: cipherXform = " & local.cipherXform);
				local.parts = local.cipherXform.split("/");
				assert(arrayLen(local.parts) == 3, "Malformed cipher transformation");
				local.cipherMode = local.parts[2];
				if(!CryptoHelper.isAllowedCipherMode(local.cipherMode)) {
					local.msg = "Cipher mode " & local.cipherMode & " is not an allowed cipher mode";
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, local.msg, local.msg));
				}
				local.keySize = readShort(local.bais);
				debug("convertToCipherText: keySize = " & local.keySize);
				local.blockSize = readShort(local.bais);
				debug("convertToCipherText: blockSize = " & local.blockSize);
				local.ivLen = readShort(local.bais);
				debug("convertToCipherText: ivLen = " & local.ivLen);
				local.iv = "";
				if(local.ivLen > 0) {
					local.iv = newByte(local.ivLen);
					local.bais.read(local.iv, 0, arrayLen(local.iv));
				}
				local.ciphertextLen = readInt(local.bais);
				debug("convertToCipherText: ciphertextLen = " & local.ciphertextLen);
				assert(local.ciphertextLen > 0, "convertToCipherText: Invalid cipher text length");
				local.rawCiphertext = newByte(local.ciphertextLen);
				local.bais.read(local.rawCiphertext, 0, arrayLen(local.rawCiphertext));
				local.macLen = readShort(local.bais);
				debug("convertToCipherText: macLen = " & local.macLen);
				local.mac = "";
				if(local.macLen > 0) {
					local.mac = newByte(local.macLen);
					local.bais.read(local.mac, 0, arrayLen(local.mac));
				}

				local.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform=local.cipherXform, keySize=local.keySize);
				local.cipherSpec.setBlockSize(local.blockSize);
				local.cipherSpec.setIV(local.iv);
				debug("convertToCipherText: CipherSpec: " & local.cipherSpec.toStringESAPI());
				local.ct = newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec);
				assert((local.ivLen > 0 && local.ct.requiresIV()), "convertToCipherText: Mismatch between IV length and cipher mode.");
				local.ct.setCiphertext(local.rawCiphertext);
				// Set this *AFTER* setting raw ciphertext because setCiphertext()
				// method also sets encryption time.
				local.ct.setEncryptionTimestamp(local.timestamp);
				if(local.macLen > 0) {
					local.ct.storeSeparateMAC(local.mac);
				}
				return local.ct;
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException ex) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Cannot deserialize byte array into CipherText object", "Cannot deserialize byte array into CipherText object", ex));
			}
			catch(java.io.IOException e) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Cannot deserialize byte array into CipherText object", "Cannot deserialize byte array into CipherText object", e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="debug" output="false">
		<cfargument type="String" name="msg" required="true"/>

		<cfscript>
			if(instance.logger.isDebugEnabled()) {
				instance.logger.debug(newJava("org.owasp.esapi.Logger").EVENT_SUCCESS, arguments.msg);
			}
		</cfscript>

	</cffunction>

</cfcomponent>