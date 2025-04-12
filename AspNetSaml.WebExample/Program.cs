using Microsoft.AspNetCore.Mvc;

// TODO: specify the certificate that your SAML provider gave you, and your app's entity ID
const string SAML_CERTIFICATE = """
	-----BEGIN CERTIFICATE-----
	BLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAHBLAH123543==
	-----END CERTIFICATE-----
	""";
const string ENTITY_ID = "[YOUR_ENTITY_ID]";

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseHttpsRedirection();


//homepage
app.MapGet("/", () =>
{
    //TODO: specify the SAML provider url here, aka "Endpoint"
	var samlEndpoint = "http://saml-provider-that-we-use.com/login/";

	var request = new Saml.AuthRequest(
		ENTITY_ID,
		"http://localhost:5000/SamlConsume"
	);

	//now send the user to the SAML provider
	var url = request.GetRedirectUrl(samlEndpoint);
    
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