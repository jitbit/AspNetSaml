# AspNetSaml

Very simple SAML 2.0 "consumer" implementation in C# (i.e. allows adding SAML single-sign-on to your ASP.NET app, but *not* to provide auth services to other apps).

Consists of **one short C# file** you can throw into your project and start using it. Originally forked from OneLogin's .NET SAML library, but we had to fix a lot of stuff...

## Usage

**1.** Call this once in your app, for example in Global.asax:
```c#
Saml.RSAPKCS1SHA256SignatureDescription.Init();
```
**2.** To redirect the user to the saml provider:
```c#
//specify the SAML provider url here
samlEndpoint = "http://saml-provider-that-we-use.com/login/";

var request = new AuthRequest(
	"http://issuerUrl", //put your app's unique ID here
	"http://www.myapp.com/SamlConsume" //assertion Consumer Url - the URL where the provider will send authenticated users back
	);
string url = request.GetRedirectUrl(samlEndpoint);
//then send your user to this "url" var
```
**3.** To validate the SAML response (assertion) you recieved from the provider (for example, in an MVC app):

```c#
//ASP.NET MVC action method... But you can easily modify the code for Web-forms etc.
public ActionResult SamlConsume()
{
	//specify the certificate that your SAML provider has given to you
	string samlCertificate = @"-----BEGIN CERTIFICATE-----
BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
-----END CERTIFICATE-----";

	Saml.Response samlResponse = new Response(samlCertificate);
	samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]); //SAML providers usually POST the data here

	if (samlResponse.IsValid())
	{
		//WOOHOO!!! user is logged in
		
		//lets extract username/firstname etc
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
			return null;
		}
		
		//user has been authenticated, put your code here, like set a cookie or something...
	}
}
```


A version of this library has been used for years in production in our [helpdesk app](https://www.jitbit.com/hosted-helpdesk/).
