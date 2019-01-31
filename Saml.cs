/*	Jitbit's simple SAML 2.0 component for ASP.NET
	https://github.com/jitbit/AspNetSaml/
	(c) Jitbit LP, 2016
	Use this freely under the MIT license (see http://choosealicense.com/licenses/mit/)
	version 1.2
*/

using System;
using System.Web;
using System.IO;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.IO.Compression;
using System.Text;
using System.Security.Cryptography;

namespace Saml
{
	/// <summary>
	/// this class adds support of SHA256 signing to .NET 4.0 and earlier
	/// (you can use it in .NET 4.5 too, if you don't want a "System.Deployment" dependency)
	/// </summary>
	public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
	{
		public RSAPKCS1SHA256SignatureDescription()
		{
			KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
			DigestAlgorithm = typeof(SHA256Managed).FullName;   // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
			FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
			DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
		}

		public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
		{
			if (key == null)
				throw new ArgumentNullException("key");

			RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
			deformatter.SetHashAlgorithm("SHA256");
			return deformatter;
		}

		public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
		{
			if (key == null)
				throw new ArgumentNullException("key");

			RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
			formatter.SetHashAlgorithm("SHA256");
			return formatter;
		}

		private static bool _initialized = false;
		public static void Init()
		{
			if(!_initialized)
				CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			_initialized = true;
		}
	}

	public class Certificate
	{
		public X509Certificate2 cert;

		public void LoadCertificate(string certificate)
		{
			LoadCertificate(StringToByteArray(certificate));
		}

		public void LoadCertificate(byte[] certificate)
		{
			cert = new X509Certificate2(certificate);
		}

		private byte[] StringToByteArray(string st)
		{
			byte[] bytes = new byte[st.Length];
			for (int i = 0; i < st.Length; i++)
			{
				bytes[i] = (byte)st[i];
			}
			return bytes;
		}
	}

	public class Response
	{
		private XmlDocument _xmlDoc;
		private Certificate _certificate;
		private XmlNamespaceManager _xmlNameSpaceManager; //we need this one to run our XPath queries on the SAML XML

		public string Xml { get { return _xmlDoc.OuterXml; } }

		public Response(string certificateStr)
		{
			RSAPKCS1SHA256SignatureDescription.Init(); //init the SHA256 crypto provider (for needed for .NET 4.0 and lower)

			_certificate = new Certificate();
			_certificate.LoadCertificate(certificateStr);
		}
		
		public Response(byte[] certificateBytes)
		{
			RSAPKCS1SHA256SignatureDescription.Init(); //init the SHA256 crypto provider (for needed for .NET 4.0 and lower)

			_certificate = new Certificate();
			_certificate.LoadCertificate(certificateBytes);
		}

		public void LoadXml(string xml)
		{
			_xmlDoc = new XmlDocument();
			_xmlDoc.PreserveWhitespace = true;
			_xmlDoc.XmlResolver = null;
			_xmlDoc.LoadXml(xml);

			_xmlNameSpaceManager = GetNamespaceManager(); //lets construct a "manager" for XPath queries
		}

		public void LoadXmlFromBase64(string response)
		{
			System.Text.UTF8Encoding enc = new System.Text.UTF8Encoding();
			LoadXml(enc.GetString(Convert.FromBase64String(response)));
		}

		public bool IsValid()
		{
			XmlNodeList nodeList = _xmlDoc.SelectNodes("//ds:Signature", _xmlNameSpaceManager);

			SignedXml signedXml = new SignedXml(_xmlDoc);

			if (nodeList.Count == 0) return false;

			signedXml.LoadXml((XmlElement)nodeList[0]);
			return ValidateSignatureReference(signedXml) && signedXml.CheckSignature(_certificate.cert, true) && !IsExpired();
		}

		//an XML signature can "cover" not the whole document, but only a part of it
		//.NET's built in "CheckSignature" does not cover this case, it will validate to true.
		//We should check the signature reference, so it "references" the id of the root document element! If not - it's a hack
		private bool ValidateSignatureReference(SignedXml signedXml)
		{
			if (signedXml.SignedInfo.References.Count != 1) //no ref at all
				return false;

			var reference = (Reference)signedXml.SignedInfo.References[0];
			var id = reference.Uri.Substring(1);

			var idElement = signedXml.GetIdElement(_xmlDoc, id);

			if (idElement == _xmlDoc.DocumentElement)
				return true;
			else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
			{
				var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
				if (assertionNode != idElement)
					return false;
			}

			return true;
		}

		private bool IsExpired()
		{
			DateTime expirationDate = DateTime.MaxValue;
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", _xmlNameSpaceManager);
			if (node != null && node.Attributes["NotOnOrAfter"] != null)
			{
				DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
			}
			return DateTime.UtcNow > expirationDate.ToUniversalTime();
		}

		public string GetNameID()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:NameID", _xmlNameSpaceManager);
			return node.InnerText;
		}

		public string GetEmail()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='User.email']/saml:AttributeValue", _xmlNameSpaceManager);

			//some providers (for example Azure AD) put email into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']/saml:AttributeValue", _xmlNameSpaceManager);

			return node == null ? null : node.InnerText;
		}

		public string GetFirstName()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='first_name']/saml:AttributeValue", _xmlNameSpaceManager);

			//some providers (for example Azure AD) put first name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']/saml:AttributeValue", _xmlNameSpaceManager);

			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='User.FirstName']/saml:AttributeValue", _xmlNameSpaceManager);

			return node == null ? null : node.InnerText;
		}

		public string GetLastName()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='last_name']/saml:AttributeValue", _xmlNameSpaceManager);

			//some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']/saml:AttributeValue", _xmlNameSpaceManager);

			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='User.LastName']/saml:AttributeValue", _xmlNameSpaceManager);

			return node == null ? null : node.InnerText;
		}

		public string GetDepartment()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department']/saml:AttributeValue", _xmlNameSpaceManager);
			return node == null ? null : node.InnerText;
		}

		public string GetPhone()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone']/saml:AttributeValue", _xmlNameSpaceManager);
			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber']/saml:AttributeValue", _xmlNameSpaceManager);
			return node == null ? null : node.InnerText;
		}

		public string GetCompany()
		{
			XmlNode node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname']/saml:AttributeValue", _xmlNameSpaceManager);

			if (node == null)
				node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='User.CompanyName']/saml:AttributeValue", _xmlNameSpaceManager);

			return node == null ? null : node.InnerText;
		}

		//returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
		//see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
		private XmlNamespaceManager GetNamespaceManager()
		{
			XmlNamespaceManager manager = new XmlNamespaceManager(_xmlDoc.NameTable);
			manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
			manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
			manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

			return manager;
		}
	}

	public class AuthRequest
	{
		public string _id;
		private string _issue_instant;

		private string _issuer;
		private string _assertionConsumerServiceUrl;

		public enum AuthRequestFormat
		{
			Base64 = 1
		}

		public AuthRequest(string issuer, string assertionConsumerServiceUrl)
		{
			RSAPKCS1SHA256SignatureDescription.Init(); //init the SHA256 crypto provider (for needed for .NET 4.0 and lower)

			_id = "_" + System.Guid.NewGuid().ToString();
			_issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

			_issuer = issuer;
			_assertionConsumerServiceUrl = assertionConsumerServiceUrl;
		}

		public string GetRequest(AuthRequestFormat format)
		{
			using (StringWriter sw = new StringWriter())
			{
				XmlWriterSettings xws = new XmlWriterSettings();
				xws.OmitXmlDeclaration = true;

				using (XmlWriter xw = XmlWriter.Create(sw, xws))
				{
					xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("ID", _id);
					xw.WriteAttributeString("Version", "2.0");
					xw.WriteAttributeString("IssueInstant", _issue_instant);
					xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
					xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

					xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
					xw.WriteString(_issuer);
					xw.WriteEndElement();

					xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
					xw.WriteAttributeString("AllowCreate", "true");
					xw.WriteEndElement();

					/*xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("Comparison", "exact");
					xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
					xw.WriteEndElement();
					xw.WriteEndElement();*/

					xw.WriteEndElement();
				}

				if (format == AuthRequestFormat.Base64)
				{
					//byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(sw.ToString());
					//return System.Convert.ToBase64String(toEncodeAsBytes);

					//https://stackoverflow.com/questions/25120025/acs75005-the-request-is-not-a-valid-saml2-protocol-message-is-showing-always%3C/a%3E
					var memoryStream = new MemoryStream();
					var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
					writer.Write(sw.ToString());
					writer.Close();
					string result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
					return result;
				}

				return null;
			}
		}

		//returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
		public string GetRedirectUrl(string samlEndpoint)
		{
			var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";

			return samlEndpoint + queryStringSeparator + "SAMLRequest=" + HttpUtility.UrlEncode(this.GetRequest(AuthRequest.AuthRequestFormat.Base64));
		}
	}
}
