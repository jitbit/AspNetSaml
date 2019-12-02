# AspNetSaml

Very simple SAML 2.0 "consumer" implementation in C#.

It's a *SAML client* library, not a *SAML server*, allows adding SAML single-sign-on to your ASP.NET app, but *not* to provide auth services to other apps.

## Installation

Consists of **one short C# file** you can throw into your project (or [install via nuget](#new-nuget)) and start using it.

## Usage

### How SAML works?

SAML workflow has 2 steps:

1. User is redirected to the SAML provider (where he authenticates)
1. User is redirected back to your app, where you validate the payload

Here's how you do it (this example is for ASP.NET MVC:

### 1. Redirecting the user to the saml provider:

```c#
//this example is an ASP.NET MVC action method
public ActionResult Login()
{
	//TODO: specify the SAML provider url here, aka "Endpoint"
	var samlEndpoint = "http://saml-provider-that-we-use.com/login/";

	var request = new AuthRequest(
		"http://www.myapp.com", //TODO: put your app's "unique ID" here
		"http://www.myapp.com/SamlConsume" //TODO: put Assertion Consumer URL (where the provider should redirect users after authenticating)
		);

	//generate the provider URL
	string url = request.GetRedirectUrl(samlEndpoint);

	//then redirect your user to the above "url" var
	//for example, like this:
	Response.Redirect(url);
}
```

### 2. User has been redirected back

User is sent back to your app - you need to validate the SAML response ("assertion") that you recieved via POST.

Here's an example of how you do it in ASP.NET MVC

```c#
//ASP.NET MVC action method... But you can easily modify the code for Web-forms etc.
public ActionResult SamlConsume()
{
	// 1. TODO: specify the certificate that your SAML provider gave you
	string samlCertificate = @"-----BEGIN CERTIFICATE-----
BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
-----END CERTIFICATE-----";

	// 2. Let's read the data - SAML providers usually POST it into the "SAMLResponse" var
	Saml.Response samlResponse = new Response(samlCertificate, Request.Form["SAMLResponse"]);

	// 3. We're done!
	if (samlResponse.IsValid())
	{
		//WOOHOO!!! user is logged in
		
		//Some more optional stuff for you
		//let's extract username/firstname etc
		string username, email, firstname, lastname;
		try
		{
			username = samlResponse.GetNameID();
			email = samlResponse.GetEmail();
			firstname = samlResponse.GetFirstName();
			lastname = samlResponse.GetLastName();
		}
		catch(Exception ex)
		{
			//insert error handling code
			//no, really, please do
			return null;
		}
		
		//user has been authenticated, put your code here, like set a cookie or something...
		//or call FormsAuthentication.SetAuthCookie() or something
	}
}
```

# Dependencies

Project should reference `System.Security`

# (NEW!) Nuget

I've published this to Nuget.

`Install-Package AspNetSaml`

This will simply add the cs-file to the root of your project.

A version of this library has been used for years in production in our [helpdesk app](https://jitbit.github.com/helpdesk/).
