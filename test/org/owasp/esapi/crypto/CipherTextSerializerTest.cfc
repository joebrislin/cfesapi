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
<cfcomponent extends="cfesapi.test.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		instance.encryptor = "";
    	instance.ivSpec = "";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			instance.encryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
	        local.ivBytes = instance.ESAPI.randomizer().getRandomBytes(instance.encryptor.getBlockSize());
	        instance.ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(local.ivBytes);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			System.out.flush();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAsSerializedByteArray" output="false">
		<cfscript>
			System.out.println("CipherTextSerializerTest.testAsSerializedByteArray() ...");
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

	        local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
	        local.cipherSpec.setIV(instance.ivSpec.getIV());
	        try {
	            local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
	            instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);

	            local.raw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("Hello").getBytes("UTF8"));
	            local.ct = instance.ESAPI.encryptor().encrypt(local.key, createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, "Hello") );
	            assertTrue( !isNull(local.ct) );   // Here to eliminate false positive from FindBugs.
	            local.cts = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextObj=local.ct );
	            local.serializedBytes = local.cts.asSerializedByteArray();
	            local.result = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI).fromPortableSerializedBytes(local.serializedBytes);
	            local.pt = instance.ESAPI.encryptor().decrypt(local.key, local.result);
	            assertTrue( "Hello" == local.pt.toString() );
	        } catch (Exception e) {
	            fail("Test failed: Caught exception: " & e.getClass().getName() & "; msg was: " & e);
	            e.printStackTrace(System.err);
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAsCipherText" output="false">
		<cfscript>
			System.out.println("CipherTextSerializerTest.testAsCipherText() ...");
	        try {
	            local.ct = instance.ESAPI.encryptor().encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, "Hello") );
	            local.cts = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextObj=local.ct );
	            local.result = local.cts.asCipherText();
	            assertTrue( local.ct.equals(local.result) );
	            local.pt = instance.ESAPI.encryptor().decrypt(ciphertext=local.result);
	            assertTrue( "Hello" == local.pt.toString() );
	        } catch (EncryptionException e) {
	            fail("Caught EncryptionException; exception msg: " & e);
	        }
    	</cfscript> 
	</cffunction>


</cfcomponent>
