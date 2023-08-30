using Saml;
using System.IO.Compression;
using System.Text;
using Shouldly;
using System.Security.Claims;

namespace AspNetSaml.Tests
{
	[TestClass]
	public class UnitTests
	{
		//cert and signature taken form here: www.samltool.com/generic_sso_res.php

		[TestMethod]
		public void TestSamlResponseValidator()
		{
			var cert = @"-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
-----END CERTIFICATE-----";

			var samlresp = new Saml.Response(cert);
			samlresp.LoadXml(@"<?xml version=""1.0""?>
<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""pfx6cdd04e4-f033-42ed-e74f-7ba72e2280e0"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"" Destination=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
    <ds:SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/>
  <ds:Reference URI=""#pfx6cdd04e4-f033-42ed-e74f-7ba72e2280e0""><ds:Transforms><ds:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><ds:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></ds:Transforms><ds:DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><ds:DigestValue>99Bke1BpL1yOfGd5ADkGSle2sZg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>OOyb3YtYQm3DC7gj6lQPM20r76HH4KvAE93f5xrIuIHGk8ZJlse4m8t4msLkhwUEAGwWOOVyHs8gChtN1m/P4pKCXyttO9Hev14Wz8E1R444kg5Yak+02FZ+Fn3VbbPq+kY4eYRkczNMphivWkdwc/QjDguNzGoKCEEtbBKDMGg=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xs=""http://www.w3.org/2001/XMLSchema"" ID=""_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier=""http://sp.example.com/demo1/metadata.php"" Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:transient"">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
        <saml:SubjectConfirmationData NotOnOrAfter=""2024-01-18T06:21:48Z"" Recipient=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685""/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=""2014-07-17T01:01:18Z"" NotOnOrAfter=""2024-01-18T06:21:48Z"">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant=""2014-07-17T01:01:48Z"" SessionNotOnOrAfter=""2024-07-17T09:01:48Z"" SessionIndex=""_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name=""uid"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=""mail"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=""eduPersonAffiliation"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
        <saml:AttributeValue xsi:type=""xs:string"">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type=""xs:string"">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
");

			samlresp.IsValid().ShouldBeTrue();
			samlresp.GetNameID().ShouldBe("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7");
			samlresp.GetEmail().ShouldBe("test@example.com");
			samlresp.GetCustomAttribute("uid").ShouldBe("test");
		}

		[TestMethod]
		public void TestSamlSignoutResponseValidator()
		{
			//this test's cert and signature borrowed from https://github.com/boxyhq/jackson/

			var cert = @"-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJcp0xLOhRU0fTMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi10eWo3cXl6ei5hdXRoMC5jb20wHhcNMTkwMzI3MTMyMTQ0WhcNMzIxMjAzMTMyMTQ0WjAhMR8wHQYDVQQDExZkZXYtdHlqN3F5enouYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyr2LHhkTEf5xO+mGjZascQ9bfzcSDmjyJ6RxfD9rAJorqVDIcq+dEtxDvo0HWt/bccX+9AZmMiqCclLRyv7Sley7BkxYra5ym8mTwmaZqUZbWyCQ15Hpq6G27yrWk8V6WKvMhJoxDqlgFh08QDOxBy5jCzwxVyFKDchJiy1TflLC8dFJLcmszQsrvl3enbQyYy9XejgniugJKElZMZknFF9LmcQWeCmwDG+2w6HcMZIXPny9Cl5GZra7wt/EWg3iwNw5ZqP41Hulf9fhilJs3bVehnDgftQTKyTUBEfCDxzaIsEmpPWAqTg5IIEKkHX4/1Rm+7ltxg+n0pIXxUrtCQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcb2UMMqwD9zCk3DOWnx/XwfKd5DAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAFE1FG/u0eYHk/R5a8gGiPgazEjmQUSMlBxjhhTU8bc0X/oLyCfJGdoXQKJVtHgKAIcvCtrHBjKDy8CwSn+J1jTMZklnpkhvXUHiEj1ViplupwuXblvhEXR2+Bkly57Uy1qoFvKHCejayRWsDaG062kEQkt5k1FtVatUGS6labThHjr8K2RyqTAYpXWqthR+wKTFLni9V2pjuoUOABBYeGTalnIOGvr/i5I+IjJDHND0x7wrveekFDI5yX9V8ZdMGiN2SkoXBMa5+o1aD3gtbi8c2HcOgjMsIzHGAj4dz/0syWfpkEkrbs7FURSvtuRLaNrH/2/rto0KgiWWuPKvm1w=
-----END CERTIFICATE-----";

			var samlresp = new Saml.SignoutResponse(cert);
			samlresp.LoadXml(@"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_716cfa40a953610d9d68"" InResponseTo=""_a0089b303b86a97080ff"" Version=""2.0"" IssueInstant=""2022-03-25T07:50:52.110Z"" Destination=""http://localhost:3000/slo""><saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">urn:dev-tyj7qyzz.auth0.com</saml:Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference URI=""#_716cfa40a953610d9d68""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>Lk9TO/DGFFLLb+29H32O/scFccU=</DigestValue></Reference></SignedInfo><SignatureValue>altTmKkKqudi+jYBZd6bETdYRbTKerUiNxFugcoD7ZmdZsRlrcNir0ZLRq+NB6nTh4zeKwGiGs03FyAW0Wdr8vgl0GQ/KOGuUrpoFNI8EID1HYrghHZMR43CgauIHGg0dw8uSjQYUcU1ICVYG2trgXC9TR81g+3XVBPBnoJWS2yV8hPc6QdFAUdb/0qUn/GPdpSPOlb6/MMUQB+K+es6HzjQfU2PEV3aNarHrKHSyFRdBHFMgtt7rUE3eAev+3/Uwq6RPBFk9huUJ6F0MRDoVjpWNzD2jByTtRv7OYInDsEJKCwJ+6pOKGVK6GDXuXnuI8s6BNEalpNJkWR8BxFVbw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDBzCCAe+gAwIBAgIJcp0xLOhRU0fTMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFmRldi10eWo3cXl6ei5hdXRoMC5jb20wHhcNMTkwMzI3MTMyMTQ0WhcNMzIxMjAzMTMyMTQ0WjAhMR8wHQYDVQQDExZkZXYtdHlqN3F5enouYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyr2LHhkTEf5xO+mGjZascQ9bfzcSDmjyJ6RxfD9rAJorqVDIcq+dEtxDvo0HWt/bccX+9AZmMiqCclLRyv7Sley7BkxYra5ym8mTwmaZqUZbWyCQ15Hpq6G27yrWk8V6WKvMhJoxDqlgFh08QDOxBy5jCzwxVyFKDchJiy1TflLC8dFJLcmszQsrvl3enbQyYy9XejgniugJKElZMZknFF9LmcQWeCmwDG+2w6HcMZIXPny9Cl5GZra7wt/EWg3iwNw5ZqP41Hulf9fhilJs3bVehnDgftQTKyTUBEfCDxzaIsEmpPWAqTg5IIEKkHX4/1Rm+7ltxg+n0pIXxUrtCQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRcb2UMMqwD9zCk3DOWnx/XwfKd5DAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAFE1FG/u0eYHk/R5a8gGiPgazEjmQUSMlBxjhhTU8bc0X/oLyCfJGdoXQKJVtHgKAIcvCtrHBjKDy8CwSn+J1jTMZklnpkhvXUHiEj1ViplupwuXblvhEXR2+Bkly57Uy1qoFvKHCejayRWsDaG062kEQkt5k1FtVatUGS6labThHjr8K2RyqTAYpXWqthR+wKTFLni9V2pjuoUOABBYeGTalnIOGvr/i5I+IjJDHND0x7wrveekFDI5yX9V8ZdMGiN2SkoXBMa5+o1aD3gtbi8c2HcOgjMsIzHGAj4dz/0syWfpkEkrbs7FURSvtuRLaNrH/2/rto0KgiWWuPKvm1w=</X509Certificate></X509Data></KeyInfo></Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status></samlp:LogoutResponse>");


			samlresp.IsValid().ShouldBeTrue();
			samlresp.GetLogoutStatus().ShouldBe("Success");
		}

		[TestMethod]
		public void TestSamlResponseValidatorAdvanced()
		{
			var cert = @"-----BEGIN CERTIFICATE-----
MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=
-----END CERTIFICATE-----";

			var samlresp = new Saml.Response(cert);
			samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");

			samlresp.IsValid().ShouldBeTrue();
			samlresp.GetCustomAttributeViaFriendlyName("givenName").ShouldBe("Guest");
			samlresp.GetCustomAttributeAsList("Role").ShouldBe(new List<string> { "uma_authorization", "offline_access", "default-roles-poc", "view-profile", "manage-account", "manage-account-links", "SimpleUser" }, ignoreOrder: true);
		}

		[TestMethod]
		public void TestSamlRequest()
		{
			var request = new AuthRequest(
				"http://www.myapp.com",
				"http://www.myapp.com/SamlConsume"
				);

			var r = request.GetRequest();

			//decode the compressed base64
			var ms = new MemoryStream(Convert.FromBase64String(r));
			var ds = new DeflateStream(ms, CompressionMode.Decompress, true);
			var output = new MemoryStream();
			ds.CopyTo(output);

			//get xml
			var str = Encoding.UTF8.GetString(output.ToArray());

			str.ShouldEndWith(@"ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" AssertionConsumerServiceURL=""http://www.myapp.com/SamlConsume"" xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""><saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">http://www.myapp.com</saml:Issuer><samlp:NameIDPolicy Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"" AllowCreate=""true"" /></samlp:AuthnRequest>");
		}

		[TestMethod]
		public void TestStringToByteArray()
		{
			//test that the old StringToByteArray was generating same result as the new Encoding.ASCII.GetBytes

			var cert = @"-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
-----END CERTIFICATE-----";


			var x = StringToByteArray(cert);
			var y = Encoding.ASCII.GetBytes(cert);

			x.SequenceEqual(y).ShouldBeTrue();
		}

		[TestMethod]
		public void TestEncryptedAssertions()
		{
			// SAML values from https://www.samltool.com/generic_sso_res.php.

			var cert = Constants.Certificates.Certificate;

			var samlresp = new Saml.Response(cert);

			var xml = @$"<?xml version=""1.0""?>
                        <samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"" Version=""2.0"" IssueInstant=""2014-07-17T01:01:48Z"" Destination=""http://sp.example.com/demo1/index.php?acs"" InResponseTo=""ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"">
                            <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
                            <samlp:Status>
                                <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
                            </samlp:Status>
                            <saml:EncryptedAssertion>
                                <xenc:EncryptedData xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#"" xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"" Type=""http://www.w3.org/2001/04/xmlenc#Element"">
	                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes128-cbc""/>
	                                <dsig:KeyInfo xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"">
		                                <xenc:EncryptedKey>
			                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-1_5""/>
			                                <xenc:CipherData>
				                                <xenc:CipherValue>Pn5IVvMXk8cdvEJHQ0VGq9WMOaV2dg4QbuCdEt8Pc1yWZLUMlOghPK0pMevLsuKyBcUz/cIoQihsroBrQONrtLzhdqndGCtaZYoOdO2Lz0T5Huesqd6iEKihrtsLf4RGj2VX3XbtdQV5R/3IdnjGCgj4zClxtJb4P7gCApeQ/uIpjIuo/f1rwn9F0A+gbL5HOSicOrLMjTJVBwPR2EtwY1g7fomkKQtJpWiq2+LsXLoSwWIYM4wHyem6U+zX9qTr2yRefiNuyz1Ye0QCN1LXQCIYFrS0Mhao4MqXNXzkktmI1/FcAbGAwReUkAGY2UuS6+9MtPDuRFOk+8h+ldrxJBU=</xenc:CipherValue>
			                                </xenc:CipherData>
		                                </xenc:EncryptedKey>
	                                </dsig:KeyInfo>
	                                <xenc:CipherData>
		                                <xenc:CipherValue>WDObtBFd84WFugFF97T0SM3jd0QE6UPhVaiaLJsWRE9/rWN2oF7d0TfiYN9RmbcWYVMVdxl26o2QMX7nKv+ufesu+GSEMApKOKKjYqGYIWvSsnoeqZGoXftjl7+axLAt7XAqT4edh4IhaxM4k3aPdEFfc+fZVNzr9djUcOF7l7tFT29M0zeO/K/y6m9lvaWiRvdLf1K1Wqw8eramYvE7FhomwbIeWJguHznKrAfxhqw6HifIot/ox1pKpmyP49HLvq5tWQexTS+iNyktXzv0wZDOKjtfOy5xd5L8iXVBhY29a0tiFcnVrEWKZ7Z/kTKrl6uuxtiD6qOmlLQpcoSc1DeXnooBJn/PhIbsQZo6uKTtzMmRc62R3d32JZRUrg/Bpjtcb6nB4Iz4SSw4gSm4w7aNGKX3DqYpTAseEg082wtY4ZX8wTcb0pRV5Gc/h7vRNGtqD1q8/gmhQdpRZ468lg==</xenc:CipherValue>
	                                </xenc:CipherData>
                                </xenc:EncryptedData>
                            </saml:EncryptedAssertion>
                            <saml:EncryptedAssertion>
                                <xenc:EncryptedData xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#"" xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"" Type=""http://www.w3.org/2001/04/xmlenc#Element"">
	                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes128-cbc""/>
	                                <dsig:KeyInfo xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#"">
		                                <xenc:EncryptedKey>
			                                <xenc:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#rsa-1_5""/>
			                                <xenc:CipherData>
				                                <xenc:CipherValue>Pn5IVvMXk8cdvEJHQ0VGq9WMOaV2dg4QbuCdEt8Pc1yWZLUMlOghPK0pMevLsuKyBcUz/cIoQihsroBrQONrtLzhdqndGCtaZYoOdO2Lz0T5Huesqd6iEKihrtsLf4RGj2VX3XbtdQV5R/3IdnjGCgj4zClxtJb4P7gCApeQ/uIpjIuo/f1rwn9F0A+gbL5HOSicOrLMjTJVBwPR2EtwY1g7fomkKQtJpWiq2+LsXLoSwWIYM4wHyem6U+zX9qTr2yRefiNuyz1Ye0QCN1LXQCIYFrS0Mhao4MqXNXzkktmI1/FcAbGAwReUkAGY2UuS6+9MtPDuRFOk+8h+ldrxJBU=</xenc:CipherValue>
			                                </xenc:CipherData>
		                                </xenc:EncryptedKey>
	                                </dsig:KeyInfo>
	                                <xenc:CipherData>
		                                <xenc:CipherValue>WDObtBFd84WFugFF97T0SM3jd0QE6UPhVaiaLJsWRE9/rWN2oF7d0TfiYN9RmbcWYVMVdxl26o2QMX7nKv+ufesu+GSEMApKOKKjYqGYIWvSsnoeqZGoXftjl7+axLAt7XAqT4edh4IhaxM4k3aPdEFfc+fZVNzr9djUcOF7l7tFT29M0zeO/K/y6m9lvaWiRvdLf1K1Wqw8eramYvE7FhomwbIeWJguHznKrAfxhqw6HifIot/ox1pKpmyP49HLvq5tWQexTS+iNyktXzv0wZDOKjtfOy5xd5L8iXVBhY29a0tiFcnVrEWKZ7Z/kTKrl6uuxtiD6qOmlLQpcoSc1DeXnooBJn/PhIbsQZo6uKTtzMmRc62R3d32JZRUrg/Bpjtcb6nB4Iz4SSw4gSm4w7aNGKX3DqYpTAseEg082wtY4ZX8wTcb0pRV5Gc/h7vRNGtqD1q8/gmhQdpRZ468lg==</xenc:CipherValue>
	                                </xenc:CipherData>
                                </xenc:EncryptedData>
                            </saml:EncryptedAssertion>
                        </samlp:Response>";

			samlresp.LoadXml(xml);

			var attributes = samlresp.GetEncryptedAttributes();

			attributes.ShouldNotBeEmpty();

			var expectedValues = new[] {
				(ClaimTypes.MobilePhone, "555-555-1234"),
				(ClaimTypes.MobilePhone, "555-555-4321"),
				(ClaimTypes.MobilePhone, "555-555-1234"),
				(ClaimTypes.MobilePhone, "555-555-4321")
				};

			attributes.ShouldBe(expectedValues);

			// The results can be filtered by claim type.
			attributes.Where(x => x.Name == ClaimTypes.MobilePhone).ShouldBe(expectedValues);
			attributes.Where(x => x.Name == ClaimTypes.Email).ShouldBeEmpty();
		}

		private static byte[] StringToByteArray(string st)
		{
			byte[] bytes = new byte[st.Length];
			for (int i = 0; i < st.Length; i++)
			{
				bytes[i] = (byte)st[i];
			}
			return bytes;
		}
	}
}
