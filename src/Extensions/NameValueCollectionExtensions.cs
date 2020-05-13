using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;

namespace Common.OAuth.Extensions
{
	public static class NameValueCollectionExtensions
	{
		public static string ToNormalizedString(this NameValueCollection collection, IList<string> excludedNames = null)
		{
			var list = new List<KeyValuePair<string, string>>();

			foreach(var key in collection.AllKeys)
			{
				if(collection[key] != null)
				{
					if(excludedNames == null || !excludedNames.Contains(key))
					{
						list.Add(new KeyValuePair<string, string>(key.ToRfc3986EncodedString(),
							collection[key].ToRfc3986EncodedString()));
					}
				}
			}

			list.Sort((left, right) => left.Key.Equals(right.Key, StringComparison.Ordinal)
				? string.Compare(left.Value, right.Value, StringComparison.Ordinal)
				: string.Compare(left.Key, right.Key, StringComparison.Ordinal));

			var normalizedString = new StringBuilder();
			foreach(var pair in list)
			{
				normalizedString.Append('&').Append(pair.Key).Append('=').Append(pair.Value);
			}
			return normalizedString.ToString().TrimStart('&');
		}
	}
}
