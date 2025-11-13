using Microsoft.AspNetCore.Identity;

namespace IdentityUserImplementation.Domain.UserEntities
{
    public class AppUserClaim : IdentityUserClaim<long> { }
    public class AppUserLogin : IdentityUserLogin<long> { }
    public class AppUserRole : IdentityUserRole<long> { }
    public class AppUserToken : IdentityUserToken<long> { }
    public class RoleClaim : IdentityRoleClaim<long> { }
}
