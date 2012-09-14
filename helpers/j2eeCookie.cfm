<cfset session.setMaxInactiveInterval(javaCast( "int", 1 )) />
<cfcookie name="jsessionid" value="" expires="now"/>