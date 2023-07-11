using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
	public interface IAESCrypto
	{
		string Encrypt(string plainText, string key);
		string Decrypt(string cipherText, string key);
	}
	
	public class Crypto : IAESCrypto
	{
		public string Encrypt(string plainText, string key)
		{
			var keyBytes = Encoding.UTF8.GetBytes(key);
			var validKeyBytes = new byte[32]; // AES 256-bit key size
	
	       	Buffer.BlockCopy(keyBytes, 0, validKeyBytes, 0, Math.Min(keyBytes.Length, validKeyBytes.Length));
	
		    using (Aes aesAlg = Aes.Create())
		    {
				aesAlg.Key = validKeyBytes;
				aesAlg.GenerateIV();
	
				var iv = aesAlg.IV;
	
				using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
				{
					var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
					var encryptedBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);
					var combinedBytes = new byte[iv.Length + encryptedBytes.Length];
					Buffer.BlockCopy(iv, 0, combinedBytes, 0, iv.Length);
					Buffer.BlockCopy(encryptedBytes, 0, combinedBytes, iv.Length, encryptedBytes.Length);
					return Convert.ToBase64String(combinedBytes);
				}
		    }
		}

		public string Decrypt(string cipherText, string key)
		{
			var combinedBytes = Convert.FromBase64String(cipherText);
		    var keyBytes = Encoding.UTF8.GetBytes(key);
			
		    var validKeyBytes = new byte[32]; // AES 256-bit key size
		    Buffer.BlockCopy(keyBytes, 0, validKeyBytes, 0, Math.Min(keyBytes.Length, validKeyBytes.Length));
		
		    var iv = new byte[16]; // IV size
		    Buffer.BlockCopy(combinedBytes, 0, iv, 0, iv.Length);
		
		    int cipherTextLength = combinedBytes.Length - iv.Length;
		    var encryptedData = new byte[cipherTextLength];
		    Buffer.BlockCopy(combinedBytes, iv.Length, encryptedData, 0, cipherTextLength);
		
		    using (Aes aesAlg = Aes.Create())
		    {
		        aesAlg.Key = validKeyBytes;
		        aesAlg.IV = iv;
		
		        using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
		        {
		            var decryptedBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
		            return Encoding.UTF8.GetString(decryptedBytes);
		        }
		    }
		}
	}
}
