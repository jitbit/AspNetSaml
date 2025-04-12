using Microsoft.AspNetCore.Mvc;

// TODO: specify the certificate that your SAML provider gave you
// your app's entity ID
// and the SAML provider's endpoint (where we should redirect the user)
const string SAML_CERTIFICATE = """
	-----BEGIN CERTIFICATE-----
	BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
	-----END CERTIFICATE-----
	""";
const string ENTITY_ID = "[YOUR_ENTITY_ID]";
const string SAML_ENDPOINT = "http://saml-provider-that-we-use.com/login/";

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseHttpsRedirection();


//homepage
app.MapGet("/", () =>
{
	var request = new Saml.AuthRequest(
		ENTITY_ID,
		"https://localhost:7009/SamlConsume"
	);

	//now send the user to the SAML provider
	var url = request.GetRedirectUrl(SAML_ENDPOINT);
    
    return Results.Content("Click <a href=\"" + url + "\">here</a> to log in", "text/html");
});


//IsP will send logged in user here
app.MapPost("/SamlConsume", ([FromForm] string samlResponse) =>
{
	var saml = new Saml.Response(SAML_CERTIFICATE, samlResponse);

	if (saml.IsValid()) //all good?
	{
		return Results.Content("Success! Logged in as user " + saml.GetNameID(), "text/html");
	}

	return Results.Unauthorized();
});


//IdP will send logout requests here
app.MapPost("/SamlLogout", ([FromForm] string samlResponse) =>
{
	var saml = new Saml.IdpLogoutRequest(SAML_CERTIFICATE, samlResponse);

	if (saml.IsValid()) //all good?
	{
		var username = saml.GetNameID();
		//pseudo-code-logout-user-from-your-system(username);
	}

	return Results.Ok();
});

app.Run();