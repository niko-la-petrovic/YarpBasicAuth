using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using YarpBasicAuth.Authentication.Handlers;
using YarpBasicAuth.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var basicAuthenticationScheme = "BasicAuthentication";

builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.Limits.MaxRequestBodySize = (long)Math.Pow(10, 9); // 1GB
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = basicAuthenticationScheme;
    options.DefaultChallengeScheme = basicAuthenticationScheme;
    options.AddScheme<BasicAuthHandler>(basicAuthenticationScheme, "Basic Authentication");
});

builder.Services.AddAuthorization(options =>
{
    //options.AddPolicy("BasicAuth", policy =>
    //{
    //    // TODO
    //});
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapReverseProxy().RequireAuthorization();

//app.MapGet("/", () => "Hello World!");

app.Run();
