using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Net;
using System.Collections.Specialized;
using System.Security.Cryptography;
using Common.OAuth.Extensions;
using System.Web;
using System.Globalization;
using Common.OAuth.Constants;

namespace Common.OAuth
{
	//TODO: Possibly add some custom exception types like: request is already signed, et...

	//TODO: Possibly consider changes to how to sign header vs. form (vs just extending)

	// 05/12/2016 - DMH - adding the new Constructor and POST method for generating POST parameters ONLY
	// Returns a NameValueCollection that contains original POST params plus the OAuth params added

	public interface IWebRequestOAuthProvider
	{
		bool ValidateSignedRequest(string consumerSecret, bool replaceWithHttps = false);
	}

	public class WebRequestOAuthProvider : IWebRequestOAuthProvider
	{
		private NameValueCollection _parameters;
		private bool _isSigned;
		private readonly HttpRequestBase _request;
		private readonly WebRequest _webRequest;
		private readonly String _baseURI;

		public NameValueCollection Parameters { get { return _parameters; } }

		public string OauthConsumerKey
		{
			get { return _parameters[OAuthFields.ConsumerKey]; }
		}

		public string OauthNonce
		{
			get { return _parameters[OAuthFields.Nonce]; }
		}

		public string OauthSignatureMethod
		{
			get { return _parameters[OAuthFields.SignatureMethod]; }
		}

		public string OauthVersion
		{
			get { return _parameters[OAuthFields.Version]; }
		}

		public string OauthTimestamp
		{
			get { return _parameters[OAuthFields.Timestamp]; }
		}

		public string OauthSignature
		{
			get { return _parameters[OAuthFields.Signature]; }
		}

		public string OauthCallback
		{
			get { return _parameters[OAuthFields.Callback]; }
		}

		/// <summary>
		/// Gets the last raw value used to compute the OAuth signature hash.
		/// </summary>
		public string SignatureBase { get; private set; }

		/// <summary>
		/// Constructor for POST Form fields generation - usually for resending to a new destination inside a form redirect.
		/// WARNING: This method scrubs OAuth fields out of the <paramref name="valuesToHash"/>. 
		/// </summary>
		/// <param name="uriDestination">string - the URI destination to send the POST params to</param>
		/// <param name="valuesToHash">NameValueCollection - zero or more name/value collections of values to include in signature hash. The original collections are not modified.</param>
		public WebRequestOAuthProvider(string uriDestination, params NameValueCollection[] valuesToHash)
		{
			_parameters = new NameValueCollection();
			valuesToHash.ToList().ForEach(values => 
				values.AllKeys.Where(x => !x.ToLower().Contains("oauth")).ToList()
				.ForEach(x => _parameters.Add(x, values[x])));
			_baseURI = uriDestination;
		}

		public WebRequestOAuthProvider(WebRequest webRequest, NameValueCollection formFields)
		{
			_webRequest = webRequest;

			// define the param populate action
			Action<NameValueCollection> populateParams = null;
			// At current, form fields in a web request need to be passed in by caller using this utility if they are to be processed
			// since content is stored in response stream.
			if (formFields != null)
			{
				populateParams = x =>
				{
					foreach (string key in formFields)
					{
						x.Add(key, formFields[key]);
					}
				};
			}

			InitProviderFromRequest(
				() => webRequest.Headers[OAuthHeaders.Authorization],
				() => webRequest.RequestUri.Query,
				populateParams
			);
		}

		/// <summary>
		/// Create a new instance baesd on an <see cref="HttpRequestBase"/>. The params to use for the signature are taken from the posted form and URL querystring.
		/// </summary>
		/// <param name="request"></param>
		public WebRequestOAuthProvider(HttpRequestBase request)
		{
			_request = request;
			InitProviderFromRequest(
				() => request.Headers[OAuthHeaders.Authorization],
				() => request.Url.Query,
				x => request.Form.AllKeys // copy all form field items into params collection
					.Where(key => key != null)
					.ToList().ForEach(
						y => x.Add(y, request.Form[y]
					)
				)
			);
		}

		private void InitProviderFromRequest(Func<string> authSelector, Func<string> querySelector, Action<NameValueCollection> populateParams)
		{
			_parameters = new NameValueCollection();

			//Authorization Header parameters
			var authorizationHeader = authSelector();

			if (authorizationHeader != null)
			{
				_parameters.Add(ParseAuthorizationHeader(authorizationHeader));
			}

			//Querystring parameters
			var queryString = querySelector();
			if (queryString != null)
			{
				_parameters.Add(HttpUtility.ParseQueryString(queryString));
			}

			// don't simplify this - library used in earlier compilers
			if (populateParams != null) 
			{
				populateParams(_parameters);
			}

			string signature = _parameters[OAuthFields.Signature];

			_isSigned = (signature != null);
		}

		private string GenerateSignatureBase(string httpMethod, Uri url, NameValueCollection parameters)
		{
			var normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
			if (!((url.Scheme == "http" && url.Port == 80) || (url.Scheme == "https" && url.Port == 443)))
			{
				normalizedUrl += ":" + url.Port;
			}
			normalizedUrl += url.AbsolutePath;

			StringBuilder signatureBase = new StringBuilder();
			signatureBase.Append(httpMethod.ToRfc3986EncodedString().ToUpper()).Append('&');
			signatureBase.Append(normalizedUrl.ToRfc3986EncodedString()).Append('&');

			//TODO: Implement constants for OAuth
			var excludedNames = new List<string> { OAuthFields.Signature, "realm" };
			signatureBase.Append(parameters.ToNormalizedString(excludedNames).ToRfc3986EncodedString());

			return signatureBase.ToString();
		}

		private string GenerateSignature(string httpMethod, Uri url, NameValueCollection parameters, string consumerSecret)
		{
			SignatureBase = GenerateSignatureBase(httpMethod, url, parameters);
			Trace.WriteLine(SignatureBase, "OAuth signature base");

			// Note that in LTI, the TokenSecret (second part of the key) is blank
			HMACSHA1 hmacsha1 = new HMACSHA1();
			hmacsha1.Key = Encoding.ASCII.GetBytes(string.Format("{0}&", consumerSecret.ToRfc3986EncodedString()));

			var dataBuffer = Encoding.ASCII.GetBytes(SignatureBase);
			var hashBytes = hmacsha1.ComputeHash(dataBuffer);

			return Convert.ToBase64String(hashBytes);
		}

		private NameValueCollection ParseAuthorizationHeader(string authorizationHeader)
		{
			var authorizationHeaderParams = new NameValueCollection();

			authorizationHeader = authorizationHeader.Replace("OAuth", "").Trim();
			foreach (var pair in authorizationHeader.Split(','))
			{
				var equalsIndex = pair.IndexOf("=");
				var key = pair.Substring(0, equalsIndex).Trim();
				//Value is just the rest of the string (may contain an equals)
				var value = HttpUtility.UrlDecode(pair.Substring(equalsIndex + 1).Trim('"'));

				// Ignore invalid key/value pairs
				if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value))
				{
					authorizationHeaderParams.Add(key, value);
				}
			}

			return authorizationHeaderParams;
		}

		private void addAuthorizationHeaderValue(bool includeBodyHash)
		{
			// construct the list of fields to include
			var fields = new List<string>
			{
				OAuthFields.ConsumerKey,
				OAuthFields.Nonce,
				OAuthFields.SignatureMethod,
				OAuthFields.Version,
				OAuthFields.Timestamp
			};
			if (includeBodyHash)
			{
				fields.Add(OAuthFields.BodyHash);
			}
			fields.Add(OAuthFields.Signature);

			// expand the fields to include their values
			fields = fields.Select(x => x = string.Format("{0}=\"{1}\"", x, _parameters[x].ToRfc3986EncodedString())).ToList();

			_webRequest.Headers[OAuthHeaders.Authorization] = string.Format("OAuth {0}", string.Join(",", fields));
		}

		public bool ValidateSignedRequest(string consumerSecret, bool replaceWithHttps = false)
		{
			string signature;
			var uri = _request.Url;
			if (replaceWithHttps)
			{
				uri = new Uri(uri.AbsoluteUri.Replace("http", "https"));
			}
			signature = GenerateSignature(_request.HttpMethod, uri, _parameters, consumerSecret);

			//If our signature matches the provided one we are looking at a valid request.
			return (signature == _parameters[OAuthFields.Signature]);
		}

		/// <summary>
		/// Augments the parameters collection with the OAuth signature params.
		/// Caution! This will include query string values (used to generate hash) in the result.
		/// </summary>
		/// <param name="consumerKey">string - the Oauth key</param>
		/// <param name="consumerSecret">string - the Oauth secret</param>
		/// <param name="callbackUrl">string - the callback url if it is needed</param>
		/// <returns>NameValueCollection - containing original POST params and the new OAuth parameters for POST in forms</returns>
		public NameValueCollection GenerateOauthSignatureParamsForFormSubmission(string consumerKey, string consumerSecret, string callbackUrl = null)
		{
			_parameters.Add(GenerateOauthSignatureParams(consumerKey, consumerSecret, callbackUrl));
			return _parameters;
		}

		/// <summary>
		/// Generates just the Oauth params needed to sign a form.
		/// </summary>
		/// <param name="consumerKey">string - the Oauth key</param>
		/// <param name="consumerSecret">string - the Oauth secret</param>
		/// <param name="callbackUrl">string - the callback url if it is needed</param>
		/// <returns>NameValueCollection - containing only the new OAuth parameters</returns>
		public NameValueCollection GenerateOauthSignatureParams(string consumerKey, string consumerSecret, string callbackUrl = null)
		{
			var result = new NameValueCollection();
			if (_baseURI == null || _parameters == null)
			{
				return result;
			}

			result.Add(OAuthFields.ConsumerKey, consumerKey);
			result.Add(OAuthFields.SignatureMethod, "HMAC-SHA1");
			result.Add(OAuthFields.Version, "1.0");
			var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			var timestamp = Convert.ToInt64(ts.TotalSeconds);
			result.Add(OAuthFields.Timestamp, timestamp.ToString(CultureInfo.InvariantCulture));
			result.Add(OAuthFields.Nonce, Guid.NewGuid().ToString());
			if (string.IsNullOrEmpty(callbackUrl))
			{
				result.Add(OAuthFields.Callback, "about:blank");
			}
			else
			{
				result.Add(OAuthFields.Callback, callbackUrl);
			}
			var signingParams = new NameValueCollection(_parameters);
			signingParams.Add(result);
			var signature = GenerateSignature("POST", new System.Uri(_baseURI), signingParams, consumerSecret);
			result.Add(OAuthFields.Signature, signature);

			return result;
		}

		//Notably byte buffer MUST be provided for body hash as the request stream is write only.
		public bool SignWebRequest(string consumerKey, string consumerSecret, bool includeAuthorizationHeader = true, bool includeBodyHash = false, byte[] buffer = null, Uri overrideUri = null)
		{
			if (_webRequest != null && !_isSigned)
			{
				//1) Add Authorization headers to parameters collection.
				if (_parameters[OAuthFields.ConsumerKey] == null)
				{
					_parameters.Add(OAuthFields.ConsumerKey, consumerKey);
				}
				_parameters.Add(OAuthFields.Nonce, Guid.NewGuid().ToString());
				if (_parameters[OAuthFields.SignatureMethod] == null)
				{
					_parameters.Add(OAuthFields.SignatureMethod, "HMAC-SHA1");
				}
				if (_parameters[OAuthFields.Version] == null)
				{
					_parameters.Add(OAuthFields.Version, "1.0");
				}
				// Calculate the timestamp
				var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
				var timestamp = Convert.ToInt64(ts.TotalSeconds);
				_parameters.Add(OAuthFields.Timestamp, timestamp.ToString(CultureInfo.InvariantCulture));

				//If we are including a body hash process it and add parameter
				if (includeBodyHash && buffer != null)
				{
					using (var sha1 = new SHA1CryptoServiceProvider())
					{
						var hash = sha1.ComputeHash(buffer);
						var hash64 = Convert.ToBase64String(hash);

						if (_parameters[OAuthFields.BodyHash] == null)
						{
							_parameters.Add(OAuthFields.BodyHash, hash64);
						}
					}
				}

				//2) Create signature
				var uriForSignature = (overrideUri != null) ? overrideUri : _webRequest.RequestUri;
				var signature = GenerateSignature(_webRequest.Method, uriForSignature, _parameters, consumerSecret);
				_parameters.Add(OAuthFields.Signature, signature);

				//3) Build Authorization Header with signature included and add to request.  Notably if it's desired in the web requests forms collection it must be requested via the oauth properties above.
				if (includeAuthorizationHeader)
				{
					addAuthorizationHeaderValue(includeBodyHash);
				}

				return true;
			}
			return false;
		}

		/// <summary>
		/// Scrubs a <see cref="NameValueCollection"/> of all OAuth parameters and returns the new list.
		/// </summary>
		/// <param name="parameters"><see cref="NameValueCollection"/> list to scrub.</param>
		/// <returns>Scrubbed list.</returns>
		public static NameValueCollection ScrubOAuthValues(NameValueCollection parameters)
		{
			var newValues = new NameValueCollection();
			parameters.AllKeys.Where(x => !x.ToLower().StartsWith("oauth")).ToList()
			.ForEach(x => newValues.Add(x, parameters[x]));
			return newValues;
		}

		public static bool IsFormSigned(NameValueCollection formData)
		{
			return formData.AllKeys.Any(x => x.ToLower() == OAuthFields.Signature);
		}

		/// <summary>
		/// Checks whether a form uses OAuth but looking for any OAuth related fields.
		/// </summary>
		/// <param name="formData"></param>
		/// <returns></returns>
		public static bool IsFormOAuth(NameValueCollection formData)
		{
			return formData.AllKeys.Any(x => x.StartsWith(OAuthFields.FieldPrefix, StringComparison.InvariantCultureIgnoreCase));
		}
	}
}
