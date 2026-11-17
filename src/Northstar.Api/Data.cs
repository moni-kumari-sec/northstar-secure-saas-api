namespace Northstar.Api;

// Synthetic data only. Fictional company: Northstar Orders.
public class UserRecord
{
    public int Id { get; set; }
    public string DisplayName { get; set; } = "";
    public string Email { get; set; } = "";
    public string Role { get; set; } = "User";
    public string TenantId { get; set; } = "";
}

public record Order(int Id, string TenantId, string Item, decimal Total);

public record UpdateProfileRequest(string? DisplayName, string? Email);

public class DataStore
{
    public List<UserRecord> Users { get; } = new()
    {
        new UserRecord { Id = 1, DisplayName = "Alice (Tenant A)", Email = "alice@tenant-a.example", Role = "User",  TenantId = "tenant-a" },
        new UserRecord { Id = 2, DisplayName = "Bob (Tenant B)",   Email = "bob@tenant-b.example",   Role = "User",  TenantId = "tenant-b" },
        new UserRecord { Id = 3, DisplayName = "Ada (Admin A)",    Email = "ada@tenant-a.example",   Role = "Admin", TenantId = "tenant-a" },
    };

    public List<Order> Orders { get; } = new()
    {
        new Order(1001, "tenant-a", "Widget", 19.99m),
        new Order(1002, "tenant-a", "Gadget", 49.50m),
        new Order(2001, "tenant-b", "Sprocket", 99.00m),
        new Order(2002, "tenant-b", "Gizmo", 5.25m),
    };

    public List<string> AuditLog { get; } = new()
    {
        "2026-01-01 admin ada@tenant-a.example exported orders",
        "2026-01-02 user bob@tenant-b.example changed email",
    };
}
