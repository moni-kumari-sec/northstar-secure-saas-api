using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Northstar.Api;

// Lab-only authentication: fixed fake tokens map to fake users. Not for production use.
public class TokenAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "LabToken";

    // token -> (user id, role, tenant). A null tenant simulates a token with no tenant claim.
    private static readonly Dictionary<string, (string Id, string Role, string? Tenant)> Tokens = new()
    {
        ["token-alice"]    = ("1", "User",  "tenant-a"),
        ["token-bob"]      = ("2", "User",  "tenant-b"),
        ["token-ada"]      = ("3", "Admin", "tenant-a"),
        ["token-notenant"] = ("9", "User",  null),
    };

    public TokenAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(header)) return Task.FromResult(AuthenticateResult.NoResult());

        var token = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] : header;
        if (!Tokens.TryGetValue(token, out var t)) return Task.FromResult(AuthenticateResult.Fail("Invalid token"));

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, t.Id),
            new(ClaimTypes.Role, t.Role),
        };
        if (t.Tenant is not null) claims.Add(new Claim("tenant_id", t.Tenant));

        var identity = new ClaimsIdentity(claims, SchemeName);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
