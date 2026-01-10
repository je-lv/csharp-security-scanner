using System;
using System.Linq;
using System.Web.Mvc;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;

namespace TestApp.Controllers
{
    public class SecureController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IAntiforgery _antiforgery;

        public SecureController(AppDbContext context, IAntiforgery antiforgery)
        {
            _context = context;
            _antiforgery = antiforgery;
        }

        // SQLI - Secure: Entity Framework LINQ
        [HttpGet]
        public ActionResult Search(string query)
        {
            var users = _context.Users
                .Where(u => u.Name.Contains(query))
                .Select(u => new { u.Id, u.Name })
                .ToList();
            return Json(users);
        }

        // SQLI - Secure: Parameterized query
        public ActionResult GetUserById(int id)
        {
            var user = _context.Users.FirstOrDefault(u => u.Id == id);
            return View(user);
        }

        // XSS - Secure: HTML encoding
        public ActionResult Profile(string bio)
        {
            ViewBag.Bio = HtmlEncoder.Default.Encode(bio);
            return View();
        }

        // CSRF - Secure: AntiForgeryToken
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult UpdateProfile(UserModel model)
        {
            if (ModelState.IsValid)
            {
                // Update user...
            }
            return View(model);
        }

        // Path - Secure: Path.GetFileName
        public ActionResult Download(string filename)
        {
            string safeName = System.IO.Path.GetFileName(filename);
            string fullPath = System.IO.Path.Combine(Server.MapPath("~/uploads/"), safeName);
            
            // Verify path is within allowed directory
            string resolvedPath = System.IO.Path.GetFullPath(fullPath);
            if (!resolvedPath.StartsWith(Server.MapPath("~/uploads/")))
            {
                return HttpNotFound();
            }
            
            byte[] fileBytes = System.IO.File.ReadAllBytes(resolvedPath);
            return File(fileBytes, "application/octet-stream");
        }

        // Crypto - Secure: BCrypt
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        // Crypto - Secure: AES
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = key;
                // Encryption logic...
                return null;
            }
        }

        // Crypto - Secure: Secure random
        public byte[] GenerateToken()
        {
            byte[] token = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(token);
            return token;
        }

        // Auth - Secure: Using Identity
        public async Task<ActionResult> Login(LoginModel model)
        {
            var result = await _signInManager.PasswordSignInAsync(
                model.Username, 
                model.Password, 
                model.RememberMe, 
                lockoutOnFailure: true);
            
            return result.Succeeded ? RedirectToAction("Index") : View(model);
        }

        // XXE - Secure: DtdProcessing.Prohibit
        public ActionResult ParseXml(string xmlData)
        {
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit
            };
            // Parse safely...
            return View();
        }

        // Deserialization - Secure: System.Text.Json
        public ActionResult ParseJson(string json)
        {
            var obj = System.Text.Json.JsonSerializer.Deserialize<UserModel>(json);
            return View(obj);
        }

        // SSRF - Secure: HttpClientFactory with validation
        public async Task<ActionResult> Fetch(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            {
                return BadRequest("Invalid URL");
            }
            
            // Whitelist check
            if (uri.Host != "api.trusted.com")
            {
                return BadRequest("Untrusted host");
            }
            
            var client = _httpClientFactory.CreateClient();
            var response = await client.GetStringAsync(uri);
            return Content(response);
        }
    }
}
