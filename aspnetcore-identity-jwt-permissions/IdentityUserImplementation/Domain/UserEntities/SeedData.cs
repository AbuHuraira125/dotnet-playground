using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityUserImplementation.Domain.UserEntities
{
    public static class SeedData
    {
        public static async Task EnsureSeedAsync(IServiceProvider sp)
        {
            var userMgr = sp.GetRequiredService<UserManager<AppUser>>();
            var roleMgr = sp.GetRequiredService<RoleManager<Role>>();

            // --- Admin user/role ---
            const string adminEmail = "admin@example.com";
            const string adminPassword = "Admin#123"; // change in production
            const string adminRoleName = "Admin";

            var admin = await userMgr.FindByEmailAsync(adminEmail);
            if (admin is null)
            {
                admin = new AppUser { UserName = adminEmail, Email = adminEmail };
                var createUser = await userMgr.CreateAsync(admin, adminPassword);
                if (!createUser.Succeeded)
                    throw new Exception("Failed to create admin user: " +
                                        string.Join(", ", createUser.Errors.Select(e => e.Description)));
            }

            if (!await roleMgr.RoleExistsAsync(adminRoleName))
            {
                var createRole = await roleMgr.CreateAsync(new Role { Name = adminRoleName });
                if (!createRole.Succeeded)
                    throw new Exception("Failed to create admin role: " +
                                        string.Join(", ", createRole.Errors.Select(e => e.Description)));
            }

            if (!await userMgr.IsInRoleAsync(admin, adminRoleName))
            {
                var addRole = await userMgr.AddToRoleAsync(admin, adminRoleName);
                if (!addRole.Succeeded)
                    throw new Exception("Failed to add admin to role: " +
                                        string.Join(", ", addRole.Errors.Select(e => e.Description)));
            }

            // --- Claims for your Module+Action policy model ---
            // Always allow everything via "AllAll"
            var existing = await userMgr.GetClaimsAsync(admin);
            if (!existing.Any(c => c.Type == "All" && c.Value == "All"))
                await userMgr.AddClaimAsync(admin, new Claim("All", "All"));

            // Typical Users CRUD claims
            var actions = new[] { "Read", "Create", "Update", "Delete" };
            foreach (var a in actions)
                if (!existing.Any(c => c.Type == "Users" && c.Value == a))
                    await userMgr.AddClaimAsync(admin, new Claim("Users", a));
        }
    }
}
