using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace TestApp
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddHttpClient();
            
            // Auth - Secure: Identity
            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>();
            
            // Auth - Secure: JWT validation
            services.AddAuthentication()
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true
                    };
                });
            
            // Config - Vulnerable: CORS allow any origin
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                // Logging - Review: Developer exception page
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // Logging - Secure: Exception handler
                app.UseExceptionHandler("/Error");
                
                // Headers - Secure: HSTS
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();

            // CSRF - Secure: SameSite cookies
            app.UseCookiePolicy(new CookiePolicyOptions
            {
                MinimumSameSitePolicy = SameSiteMode.Strict
            });

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                // Routing - Attack surface: MVC routes
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");

                endpoints.MapControllerRoute(
                    name: "api",
                    pattern: "api/{controller}/{action}");

                // Routing - Attack surface: Minimal API
                endpoints.MapGet("/health", () => "OK");
                endpoints.MapPost("/api/data", async (DataModel model) => { });
                endpoints.MapPut("/api/data/{id}", async (int id, DataModel model) => { });
                endpoints.MapDelete("/api/data/{id}", async (int id) => { });
            });
        }
    }

    // Models with input binding
    public class DataModel
    {
        [FromBody]
        public string Content { get; set; }
        
        [FromQuery]
        public int Page { get; set; }
        
        [FromRoute]
        public int Id { get; set; }
        
        [FromHeader]
        public string Authorization { get; set; }
    }
}
