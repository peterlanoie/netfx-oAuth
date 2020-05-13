using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Common.OAuth.Constants
{
	public static class OAuthFields
	{
		public const string FieldPrefix = "oauth_";
		public const string ConsumerKey = "oauth_consumer_key";
		public const string Nonce = "oauth_nonce";
		public const string SignatureMethod = "oauth_signature_method";
		public const string Version = "oauth_version";
		public const string Timestamp = "oauth_timestamp";
		public const string Signature = "oauth_signature";
		public const string Callback = "oauth_callback";
		public const string BodyHash = "oauth_body_hash";
		
	}

}
