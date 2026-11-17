using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Northstar.Api.Tests;

public class SecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public SecurityTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private HttpClient As(string? token)
    {
        var client = _factory.CreateClient();
        if (token is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static HttpRequestMessage Patch(string url, object body) =>
        new(HttpMethod.Patch, url) { Content = JsonContent.Create(body) };

    private async Task<string?> RoleOf(string token, int userId)
    {
        var json = await As(token).GetFromJsonAsync<JsonElement>($"/users/{userId}");
        return json.GetProperty("role").GetString();
    }

    // ---------- SEC-01: broken object-level authorization (BOLA) ----------

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Owner_CanReadOwnOrder()
        => Assert.Equal(HttpStatusCode.OK, (await As("token-alice").GetAsync("/orders/1001")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_TenantA_CannotReadTenantBOrder()
        => Assert.Equal(HttpStatusCode.NotFound, (await As("token-alice").GetAsync("/orders/2001")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Bypass_AlternateId()
        => Assert.Equal(HttpStatusCode.NotFound, (await As("token-alice").GetAsync("/orders/2002")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Bypass_OtherTenantUserCannotReadTenantAOrder()
        => Assert.Equal(HttpStatusCode.NotFound, (await As("token-bob").GetAsync("/orders/1001")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Bypass_OmittedTenantClaim()
        => Assert.Equal(HttpStatusCode.NotFound, (await As("token-notenant").GetAsync("/orders/1001")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Bypass_AlternateHttpMethod()
    {
        var put = await As("token-alice").PutAsync("/orders/2001", JsonContent.Create(new { item = "x" }));
        Assert.NotEqual(HttpStatusCode.OK, put.StatusCode);
        var del = await As("token-alice").DeleteAsync("/orders/2001");
        Assert.NotEqual(HttpStatusCode.OK, del.StatusCode);
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec01_Bypass_NoToken()
        => Assert.Equal(HttpStatusCode.Unauthorized, (await As(null).GetAsync("/orders/1001")).StatusCode);

    // ---------- SEC-02: broken function-level authorization (BFLA) ----------

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Admin_CanReadAuditLog()
        => Assert.Equal(HttpStatusCode.OK, (await As("token-ada").GetAsync("/admin/audit")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_NormalUser_CannotReadAuditLog()
        => Assert.Equal(HttpStatusCode.Forbidden, (await As("token-alice").GetAsync("/admin/audit")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Bypass_NoToken()
        => Assert.Equal(HttpStatusCode.Unauthorized, (await As(null).GetAsync("/admin/audit")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Bypass_TrailingSlash()
        => Assert.NotEqual(HttpStatusCode.OK, (await As("token-alice").GetAsync("/admin/audit/")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Bypass_DifferentCase()
        => Assert.NotEqual(HttpStatusCode.OK, (await As("token-alice").GetAsync("/ADMIN/AUDIT")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Bypass_OtherTenantUser()
        => Assert.Equal(HttpStatusCode.Forbidden, (await As("token-bob").GetAsync("/admin/audit")).StatusCode);

    [Fact, Trait("Category", "Security")]
    public async Task Sec02_Bypass_AlternateHttpMethod()
        => Assert.NotEqual(HttpStatusCode.OK, (await As("token-alice").PostAsync("/admin/audit", null)).StatusCode);

    // ---------- SEC-03: mass assignment ----------

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_User_CanUpdateOwnDisplayName()
    {
        var res = await As("token-alice").SendAsync(Patch("/users/1", new { displayName = "Alice Updated" }));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_User_CannotSetOwnRole()
    {
        await As("token-alice").SendAsync(Patch("/users/1", new { displayName = "Alice", role = "Admin" }));
        Assert.Equal("User", await RoleOf("token-alice", 1));
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_Bypass_UppercaseFieldName()
    {
        await As("token-alice").SendAsync(Patch("/users/1", new Dictionary<string, object> { ["ROLE"] = "Admin" }));
        Assert.Equal("User", await RoleOf("token-alice", 1));
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_Bypass_NestedObject()
    {
        await As("token-alice").SendAsync(Patch("/users/1", new { user = new { role = "Admin" } }));
        Assert.Equal("User", await RoleOf("token-alice", 1));
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_Bypass_CannotChangeTenant()
    {
        await As("token-alice").SendAsync(Patch("/users/1", new { tenantId = "tenant-b" }));
        var json = await As("token-alice").GetFromJsonAsync<JsonElement>("/users/1");
        Assert.Equal("tenant-a", json.GetProperty("tenantId").GetString());
    }

    [Fact, Trait("Category", "Security")]
    public async Task Sec03_Bypass_CannotEditAnotherUser()
        => Assert.Equal(HttpStatusCode.NotFound,
            (await As("token-alice").SendAsync(Patch("/users/2", new { displayName = "pwned" }))).StatusCode);
}
