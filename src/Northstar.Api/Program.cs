using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Northstar.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<DataStore>();
builder.Services.AddAuthentication(TokenAuthHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, TokenAuthHandler>(TokenAuthHandler.SchemeName, null);
builder.Services.AddAuthorization(options =>
{
    // Deny by default: every endpoint needs a signed-in user unless explicitly allowed otherwise.
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    options.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// VULNERABLE (SEC-01): trusts the ID from the URL. No tenant check, so any signed-in user can read any order.
app.MapGet("/orders/{id:int}", (int id, DataStore db) =>
{
    var order = db.Orders.FirstOrDefault(o => o.Id == id);
    return order is null ? Results.NotFound() : Results.Ok(order);
});

// SEC-02: function-level check. Only the Admin role may read the audit log.
app.MapGet("/admin/audit", (DataStore db) => Results.Ok(db.AuditLog))
   .RequireAuthorization("AdminOnly");

// A user can read only their own profile.
app.MapGet("/users/{id:int}", (int id, ClaimsPrincipal user, DataStore db) =>
{
    if (user.FindFirstValue(ClaimTypes.NameIdentifier) != id.ToString()) return Results.NotFound();
    var record = db.Users.FirstOrDefault(u => u.Id == id);
    return record is null ? Results.NotFound() : Results.Ok(record);
});

// SEC-03: mass assignment. The request type has only the fields a user may change.
// Role and tenant are not on it, so they cannot be set from the request body.
app.MapPatch("/users/{id:int}", (int id, UpdateProfileRequest req, ClaimsPrincipal user, DataStore db) =>
{
    if (user.FindFirstValue(ClaimTypes.NameIdentifier) != id.ToString()) return Results.NotFound();
    var record = db.Users.FirstOrDefault(u => u.Id == id);
    if (record is null) return Results.NotFound();

    if (req.DisplayName is not null) record.DisplayName = req.DisplayName;
    if (req.Email is not null) record.Email = req.Email;
    return Results.Ok(record);
});

app.Run();

public partial class Program { }
