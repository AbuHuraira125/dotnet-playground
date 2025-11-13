using IdentityUserImplementation.Domain.UserEntities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;

namespace IdentityUserImplementation.Models
{
    public class AppDbContext : IdentityDbContext<
        AppUser, Role, long,
        AppUserClaim, AppUserRole, AppUserLogin,
        RoleClaim, AppUserToken>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Menu> Menus => Set<Menu>();
        public DbSet<RoleMenu> RoleMenus => Set<RoleMenu>();
    }
}
