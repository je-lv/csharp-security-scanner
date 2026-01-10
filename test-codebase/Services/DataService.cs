using System;
using System.Data.OleDb;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Soap;
using Newtonsoft.Json;

namespace TestApp.Services
{
    public class DataService
    {
        // SQLI - Vulnerable: OleDbConnection
        public void ExecuteQuery(string userInput)
        {
            using (var conn = new OleDbConnection("Provider=..."))
            {
                conn.Open();
                var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT * FROM Data WHERE Field = '" + userInput + "'";
                var reader = cmd.ExecuteReader();
            }
        }

        // SQLI - Vulnerable: String.Format
        public void GetRecords(string table)
        {
            string sql = String.Format("SELECT * FROM {0}", table);
        }

        // SQLI - Vulnerable: sp_executesql
        public void DynamicQuery(string filter)
        {
            // exec sp_executesql @sql
        }

        // Deserialization - Vulnerable: TypeNameHandling
        public object DeserializeJson(string json)
        {
            var settings = new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All
            };
            return JsonConvert.DeserializeObject(json, settings);
        }

        // Deserialization - Vulnerable: SoapFormatter
        public object DeserializeSoap(byte[] data)
        {
            var formatter = new SoapFormatter();
            using (var stream = new System.IO.MemoryStream(data))
            {
                return formatter.Deserialize(stream);
            }
        }

        // Command Injection - Vulnerable: Shell execution
        public void RunCommand(string args)
        {
            Process.Start("powershell.exe", args);
        }

        // Command Injection - Vulnerable: Arguments concatenation
        public void ExecuteScript(string script)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/bin/bash";
            psi.Arguments = "-c " + script;
            Process.Start(psi);
        }

        // Crypto - Vulnerable: SHA1
        public byte[] ComputeHash(byte[] data)
        {
            using (var sha1 = System.Security.Cryptography.SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        // Crypto - Vulnerable: DES
        public void EncryptWithDES()
        {
            var des = System.Security.Cryptography.DES.Create();
        }

        // Crypto - Vulnerable: ECB mode
        public void InsecureEncryption()
        {
            var aes = System.Security.Cryptography.Aes.Create();
            aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        }

        // Crypto - Vulnerable: Hardcoded key
        private byte[] Key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        private byte[] IV = Convert.FromBase64String("AAAAAAAAAAAAAAAA");

        // Crypto - Vulnerable: Certificate validation bypass
        public void DisableCertValidation()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
        }

        // Crypto - Vulnerable: Insecure TLS
        public void SetInsecureTls()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls11;
        }

        // Auth - Vulnerable: JWT validation disabled
        public void ConfigureJwt()
        {
            var parameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };
        }

        // Logging - Vulnerable: Sensitive data in logs
        public void LogUserAction(string username, string password)
        {
            _logger.Info($"User {username} logged in with password {password}");
        }

        // Config - Vulnerable: CORS allow all
        public void ConfigureCors()
        {
            // AllowAnyOrigin is insecure
        }

        // CSRF - Vulnerable: IgnoreAntiforgeryToken
        [IgnoreAntiforgeryToken]
        public void UnsafeAction()
        {
        }
    }

    // Secure patterns
    public class SecureDataService
    {
        private readonly ILogger<SecureDataService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;

        // SQLI - Secure: Dapper parameterized
        public void GetUser(int id)
        {
            // connection.Query<User>("SELECT * FROM Users WHERE Id = @Id", new { Id = id });
        }

        // Crypto - Secure: PBKDF2
        public byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(password, salt, 100000))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        // Crypto - Secure: HMAC
        public byte[] ComputeHmac(byte[] data, byte[] key)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        // Auth - Secure: Password policy
        public void ConfigureIdentity()
        {
            // RequireDigit = true
            // RequiredLength = 12
            // RequireNonAlphanumeric = true
            // RequireUppercase = true
        }

        // Headers - Secure
        public void ConfigureHeaders()
        {
            // UseHsts()
            // Content-Security-Policy
            // X-Frame-Options: DENY
            // X-Content-Type-Options: nosniff
        }

        // SSRF - Secure: URI validation
        public bool ValidateUrl(string url)
        {
            return Uri.IsWellFormedUriString(url, UriKind.Absolute);
        }

        // XXE - Secure: XDocument
        public void ParseXml(string xml)
        {
            var doc = System.Xml.Linq.XDocument.Parse(xml);
        }

        // Command Injection - Secure
        public void SafeProcess()
        {
            var psi = new ProcessStartInfo
            {
                UseShellExecute = false,
                FileName = "/usr/bin/myapp"
            };
        }
    }
}
