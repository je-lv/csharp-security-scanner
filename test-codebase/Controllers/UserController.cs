using System;
using System.Data.SqlClient;
using System.Web.Mvc;
using System.IO;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;

namespace TestApp.Controllers
{
    public class UserController : Controller
    {
        // SQLI - Vulnerable: String concatenation
        [HttpPost]
        public ActionResult Search(string query)
        {
            string sql = "SELECT * FROM Users WHERE Name = '" + query + "'";
            // Execute query...
            return View();
        }

        // SQLI - Vulnerable: Interpolated string
        public ActionResult GetUser(int id)
        {
            string sql = $"SELECT * FROM Users WHERE Id = {id}";
            return View();
        }

        // XSS - Vulnerable: Html.Raw
        public ActionResult Profile(string bio)
        {
            ViewBag.Bio = Html.Raw(bio);
            return View();
        }

        // XSS - Vulnerable: Response.Write
        public void RenderContent(string content)
        {
            Response.Write("<div>" + content + "</div>");
        }

        // Path Traversal - Vulnerable: Unsanitized file access
        public ActionResult Download(string filename)
        {
            string path = Server.MapPath("~/uploads/") + filename;
            byte[] fileBytes = System.IO.File.ReadAllBytes(path);
            return File(fileBytes, "application/octet-stream");
        }

        // Command Injection - Vulnerable
        public ActionResult Ping(string host)
        {
            var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c ping " + host;
            process.Start();
            return View();
        }

        // XXE - Vulnerable: XmlTextReader
        public ActionResult ParseXml(string xmlData)
        {
            XmlTextReader reader = new XmlTextReader(new StringReader(xmlData));
            // Parse XML...
            return View();
        }

        // Deserialization - Vulnerable: BinaryFormatter
        public ActionResult Deserialize(byte[] data)
        {
            var formatter = new BinaryFormatter();
            using (var stream = new MemoryStream(data))
            {
                var obj = formatter.Deserialize(stream);
                return View(obj);
            }
        }

        // SSRF - Vulnerable: URL from request
        public ActionResult Fetch()
        {
            string url = Request.QueryString["url"];
            var client = new System.Net.WebClient();
            string content = client.DownloadString(url);
            return Content(content);
        }

        // Crypto - Vulnerable: MD5
        public string HashPassword(string password)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }

        // Auth - Vulnerable: Custom password comparison
        public bool ValidateUser(string inputPassword, string storedPassword)
        {
            if (inputPassword == storedPassword)
            {
                return true;
            }
            return false;
        }
    }
}
