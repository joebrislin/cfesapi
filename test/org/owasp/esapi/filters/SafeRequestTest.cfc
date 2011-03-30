<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">


	<cffunction access="public" returntype="void" name="testGetRequestParameters" output="false">
		<cfscript>
			System.out.println( "getRequestParameters");
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.request.addParameter( "one","1" );
			local.request.addParameter( "two","2" );
			local.request.addParameter( "one","3" );
			local.request.addParameter( "one","4" );
			local.safeRequest = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.request );
			local.params = local.safeRequest.getParameterValues("one");
			local.out = "";
			for (local.i = 1; local.i <= arrayLen(local.params); local.i++ ) {
				local.out &= local.params[i];
			}
			assertEquals( "134", local.out );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryStringNull" output="false">
		<cfscript>
			local.req = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");

			local.req.setQueryString("");
			local.wrappedReq = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.req);
			assertIsEmpty(local.wrappedReq.getQueryString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryStringNonNull" output="false">
		<cfscript>
			local.req = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");

			local.req.setQueryString("a=b");
			local.wrappedReq = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.req);
			assertEquals("a=b",local.wrappedReq.getQueryString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryStringNUL" output="false">
		<cfscript>
			local.req = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");

			local.req.setQueryString("a=\u0000");
			local.wrappedReq = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.req);
			assertEquals("",local.wrappedReq.getQueryString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryStringPercent" output="false">
		<cfscript>
			local.req = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");

			local.req.setQueryString("a=%62");
			local.wrappedReq = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.req);
			assertEquals("a=b",local.wrappedReq.getQueryString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryStringPercentNUL" output="false">
		<cfscript>
			local.req = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");

			local.req.setQueryString("a=%00");
			local.wrappedReq = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.req);
			assertEquals("",local.wrappedReq.getQueryString());
		</cfscript>
	</cffunction>

	<!---  Test to ensure null-value contract defined by ServletRequest.getParameterNames(String) is met. --->

	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsNullWhenParameterDoesNotExistInRequest" output="false">
		<cfscript>
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.request.clearParameters();

			local.paramName = "nonExistentParameter";
			assertIsEmptyArray(local.request.getParameterValues(local.paramName));

			local.safeRequest = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.request);
			assertIsEmptyArray(local.safeRequest.getParameterValues(local.paramName), "Expecting null value to be returned for non-existent parameter.");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsCorrectValueWhenParameterExistsInRequest" output="false">
		<cfscript>
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.request.clearParameters();

			local.paramName = "existentParameter";
			local.paramValue = "foobar";
			local.request.addParameter(local.paramName, local.paramValue);
			assertTrue(local.request.getParameterValues(local.paramName)[1] == local.paramValue);

			local.safeRequest = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.request);
			local.actualParamValue = local.safeRequest.getParameterValues(local.paramName)[1];
			assertEquals(local.paramValue, local.actualParamValue);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameterValuesReturnsCorrectValuesWhenParameterExistsMultipleTimesInRequest" output="false">
		<cfscript>
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.request.clearParameters();

			local.paramName = "existentParameter";
			local.paramValue_0 = "foobar";
			local.paramValue_1 = "barfoo";
			local.request.addParameter(local.paramName, local.paramValue_0);
			local.request.addParameter(local.paramName, local.paramValue_1);
			assertTrue(local.request.getParameterValues(local.paramName)[1] == local.paramValue_0);
			assertTrue(local.request.getParameterValues(local.paramName)[2] == local.paramValue_1);

			local.safeRequest = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init( instance.ESAPI, local.request);
			local.actualParamValues = local.safeRequest.getParameterValues(local.paramName);
			assertEquals(local.paramValue_0, local.actualParamValues[1]);
			assertEquals(local.paramValue_1, local.actualParamValues[2]);
		</cfscript>
	</cffunction>


</cfcomponent>
