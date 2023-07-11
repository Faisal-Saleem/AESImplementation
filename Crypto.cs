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
			byte[] keyBytes = Encoding.UTF8.GetBytes(key);
			byte[] validKeyBytes = new byte[32]; // AES 256-bit key size

			Array.Copy(keyBytes, validKeyBytes, Math.Min(keyBytes.Length, validKeyBytes.Length));

			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = validKeyBytes;
				aesAlg.GenerateIV();

				byte[] iv = aesAlg.IV;

				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
					{
						byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
						csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
						csEncrypt.FlushFinalBlock();

						byte[] encryptedBytes = msEncrypt.ToArray();
						byte[] combinedBytes = iv.Concat(encryptedBytes).ToArray();
						return Convert.ToBase64String(combinedBytes);
					}
				}
			}
		}

		public string Decrypt(string cipherText, string key)
		{
			byte[] combinedBytes = Convert.FromBase64String(cipherText);
			byte[] keyBytes = Encoding.UTF8.GetBytes(key);
			byte[] validKeyBytes = new byte[32]; // AES 256-bit key size

			Array.Copy(keyBytes, validKeyBytes, Math.Min(keyBytes.Length, validKeyBytes.Length));

			byte[] iv = new byte[16]; // IV size
			Array.Copy(combinedBytes, iv, iv.Length);

			byte[] encryptedData = new byte[combinedBytes.Length - iv.Length];
			Array.Copy(combinedBytes, iv.Length, encryptedData, 0, encryptedData.Length);

			using (Aes aesAlg = Aes.Create())
			{
				aesAlg.Key = validKeyBytes;
				aesAlg.IV = iv;

				using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
						{
							return srDecrypt.ReadToEnd();
						}
					}
				}
			}
		}
	}
}
