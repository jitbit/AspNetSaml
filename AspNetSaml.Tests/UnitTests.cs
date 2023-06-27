using Saml;
using System.IO.Compression;
using System.IO;
using System.Text;

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
            Assert.IsTrue(samlresp.IsValid());

            Assert.IsTrue(samlresp.GetNameID() == "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7");

            Assert.IsTrue(samlresp.GetEmail() == "test@example.com");

            Assert.IsTrue(samlresp.GetCustomAttribute("uid") == "test");
        }

        [TestMethod]
        public void TestSamlResponseValidatorAdvanced()
        {
            var cert = @"-----BEGIN CERTIFICATE-----
MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=
-----END CERTIFICATE-----";

            var samlresp = new Saml.Response(cert);
            samlresp.LoadXml(@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" Destination=""http://localhost:5167/Home/SamlConsume"" ID=""ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae"" InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><dsig:Signature xmlns:dsig=""http://www.w3.org/2000/09/xmldsig#""><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><dsig:SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><dsig:Reference URI=""#ID_c5a5b7f0-91f3-4d71-90d2-df63c1101bae""><dsig:Transforms><dsig:Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><dsig:Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></dsig:Transforms><dsig:DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><dsig:DigestValue>UrJzr9Ja0f4Ks+K6TPEfQ53bw1veGXHtMZpLmRrr/ww=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>EAM65nY/e0YkK/H0nw+hdt6PhUIEs5jtftvP/NuHCSFjsVNj8L4jIT7Gvso8r9gSnwz0FJetVK16LjHdN+0f8Od2BDk9njD7KBQx9v9ich12zl1Ny+T6dLtc4XypkvoPwscna7KIQOEn8xeKBq4IbC+gPYfJEQ3GjnQ5JuXhJW5GValLELKWbH21oECRL6VAs7BAohQy2/BbTTGM1tbeuqWIZrqdP/KKOpiHxVIPwzwC8EuQmrhYiaJ9tOzNtBJGD5IW7L6Z6GIhVX2yQPuEW/gfb/bYCi6+0KD664YBICfyJLSarbcK6qgafP9YUdJ48qopiHXbuZ1m8ceCfC0Kow==</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIClTCCAX0CBgGICgolYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANQT0MwHhcNMjMwNTExMDg1ODM3WhcNMzMwNTExMDkwMDE3WjAOMQwwCgYDVQQDDANQT0MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdKUug5y3ifMXH2kPGPib3APKzA1n9GEsAV304irs9oKK91iCpmQL0SfmMRtyWILPUTSSfKb+Ius2U9AgcjIs517DsbZYTZAglpuZ1DUZTN4IM2PRBrt2bpKv8vQTplesKw6QnWFGrjlOPtw1UmsTnciqiy71GHssSNlLvMObpyW02tt0mGbWQRvCeIwt+aXTB2xrK7buBNJ8yUwdJ0VOpfsUR0yLmV2N/oN0F+f1I/kxn/COEgFZiqJWWEyRCMCXafetU+dq8YMtcO149CKxK66WgTyanAjBf2jv7v5Gk3/0vrLFEIPtHBonDFFQeGw/sTV6bJG+tIS1CX5R/guZRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEdXFmQ0BNE4IrE+aEueIl/eyyb90jdU1gmtlrqIvR+RsuQlJzasjE5qW1vcZTdV+omQpeePnIY94KwkhbWwaMsshq7Zi7bbyNWmhc0Mo3o6ONbr3Q6fvfNBePbObGfVCFRT3mgwiqrR59Wmku4PopRS/DXYvbQoim5rxiClAHyN0PkcX6u5J7mmzV1RiZ5OE4fJkIHXXmvUc6NeeFOx8EUnEDrVbfyBn9AK0IZAoj7/jKAJPv5DsBZH3iuFwjSOCAIkpr3W0YcITBeRAvdAri9eFpJ3GO1ZKjynpQaUNWeB3JBjJeNBfQszzmEHlv3Lrayiv2+/uTjFZ2DT7jfxaMw=</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature><samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success"" /></samlp:Status><saml:Assertion xmlns=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""ID_4f3af568-ac8a-479f-ba5e-c41a665556cf"" IssueInstant=""2023-05-24T16:18:35.039Z"" Version=""2.0""><saml:Issuer>http://keycloak:1080/realms/POC</saml:Issuer><saml:Subject><saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">guest</saml:NameID><saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer""><saml:SubjectConfirmationData InResponseTo=""_336f6f63-3890-4efb-b4d5-332d3d7486ff"" NotOnOrAfter=""2024-01-18T16:18:33.039Z"" Recipient=""http://localhost:5167/Home/SamlConsume"" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=""2023-05-24T16:18:33.039Z"" NotOnOrAfter=""2024-01-18T16:18:33.039Z""><saml:AudienceRestriction><saml:Audience>WebApp3</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=""2023-05-24T16:18:35.039Z"" SessionIndex=""f954efd3-4332-4ff8-8cb7-8600174f22b0::f8e67f48-0a80-457e-a669-1e37bd0338d1"" SessionNotOnOrAfter=""2023-05-25T02:18:35.039Z""><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=""email"" Name=""urn:oid:1.2.840.113549.1.9.1"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">guest@guest.com</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""surname"" Name=""urn:oid:2.5.4.4"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute FriendlyName=""givenName"" Name=""urn:oid:2.5.4.42"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">Guest</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">uma_authorization</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">offline_access</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">default-roles-poc</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">view-profile</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">manage-account-links</saml:AttributeValue></saml:Attribute><saml:Attribute Name=""Role"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic""><saml:AttributeValue xmlns:xs=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""xs:string"">SimpleUser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>");
            
            Assert.IsTrue(samlresp.IsValid());

            Assert.IsTrue(samlresp.GetCustomAttributeViaFriendlyName("givenName") == "Guest");

            Assert.IsTrue(Enumerable.SequenceEqual(samlresp.GetCustomAttributeAsList("Role"), new List<string> { "uma_authorization", "offline_access", "default-roles-poc", "view-profile", "manage-account", "manage-account-links", "SimpleUser" }));
        }

        [TestMethod]
        public void TestSamlRequest()
        {
			var samlEndpoint = "http://saml-provider-that-we-use.com/login/";

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

            Assert.IsTrue(str.EndsWith(@"ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"" AssertionConsumerServiceURL=""http://www.myapp.com/SamlConsume"" xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""><saml:Issuer xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">http://www.myapp.com</saml:Issuer><samlp:NameIDPolicy Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"" AllowCreate=""true"" /></samlp:AuthnRequest>"));

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
            Assert.IsTrue(x.SequenceEqual(y));
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