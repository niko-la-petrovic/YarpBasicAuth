using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using YarpBasicAuth.Models;

namespace YarpBasicAuth.Authentication.Handlers;

public class BasicAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IEnumerable<BasicAuthUser> _authUsers;

    public BasicAuthHandler(
        IConfiguration configuration,
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(
            options,
            logger,
            encoder,
            clock)
    {
        _authUsers = configuration
            .GetSection("Authentication:Basic:Users")
            .Get<List<BasicAuthUser>>() ?? new List<BasicAuthUser>();
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers["Authorization"].ToString();
        if (header != null && header.StartsWith("basic", StringComparison.OrdinalIgnoreCase))
        {
            var token = header["Basic ".Length..].Trim();
            var credentialstring = Encoding.UTF8.GetString(Convert.FromBase64String(token));
            var credentials = credentialstring.Split(':');
            var username = credentials[0];
            var password = credentials[1];

            // TODO calculate password hash and compared to stored hash, rather than stored plaintext
            var user = _authUsers.FirstOrDefault(u => u.Username == username && u.Password == password);

            if (user is not null)
            {
                var claims = new[] { new Claim(ClaimTypes.NameIdentifier, username), new Claim(ClaimTypes.Role, "Admin") };
                var identity = new ClaimsIdentity(claims, "Basic");
                var claimsPrincipal = new ClaimsPrincipal(identity);
                return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name)));
            }
        }

        Response.StatusCode = 401;
        Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{Request.Host}\"");
        return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
    }
}
