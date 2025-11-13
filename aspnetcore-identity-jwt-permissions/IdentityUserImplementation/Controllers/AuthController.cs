using System.Security.Claims;
using IdentityUserImplementation.Domain.UserEntities; // AppUser, Role
using IdentityUserImplementation.Dtos;
using IdentityUserImplementation.Services;            // ITokenService (your JWT creator)
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityUserImplementation.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<AppUser> _signIn;
        private readonly UserManager<AppUser> _users;
        private readonly RoleManager<Role> _roles;
        private readonly ITokenService _tokens;

        public AuthController(
            SignInManager<AppUser> signIn,
            UserManager<AppUser> users,
            RoleManager<Role> roles,
            ITokenService tokens)
        {
            _signIn = signIn;
            _users = users;
            _roles = roles;
            _tokens = tokens;
        }


        // ============================================================
        // 1) USERS  ->  AspNetUsers
        // ============================================================


        /// <summary>
        /// Creates a user: INSERT into AspNetUsers (+ password hash etc.)
        /// </summary>
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var user = new AppUser { UserName = dto.Email, Email = dto.Email };

            // Writes a row to AspNetUsers (PasswordHash, SecurityStamp, etc.)
            var res = await _users.CreateAsync(user, dto.Password);
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "Registered", user.Id, user.Email });
        }


        /// <summary>
        /// Validates password (no table writes), then issues JWT (we do NOT store JWT in DB).
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _users.FindByEmailAsync(dto.Email);
            if (user is null) return Unauthorized();

            // Checks password, can update lockout columns in AspNetUsers on failures
            var check = await _signIn.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);
            if (!check.Succeeded) return Unauthorized();

            var token = await _tokens.CreateTokenAsync(user); // reads roles/claims, but no writes
            return Ok(new { token });
        }


        // ============================================================
        // 2) ROLES  ->  AspNetRoles
        // ============================================================

        /// <summary>
        /// Creates a role: INSERT into AspNetRoles.
        /// </summary>
        [HttpPost("roles")]
        [Authorize(Policy = "UsersUpdate")] // or your custom [AuthorizePolicy("UsersUpdate")]
        public async Task<IActionResult> CreateRole([FromBody] RoleDto dto)
        {
            if (await _roles.RoleExistsAsync(dto.RoleName)) return Ok(new { message = "Role exists" });

            var res = await _roles.CreateAsync(new Role { Name = dto.RoleName });
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "Role created", dto.RoleName });
        }


        // ============================================================
        // 3) USER ↔ ROLE  ->  AspNetUserRoles (junction)
        // ============================================================

        /// <summary>
        /// Adds a user to a role: INSERT into AspNetUserRoles (UserId, RoleId).
        /// </summary>
        [HttpPost("users/{userId:long}/roles")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> AddUserToRole(long userId, [FromBody] RoleDto dto)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            if (!await _roles.RoleExistsAsync(dto.RoleName))
            {
                var create = await _roles.CreateAsync(new Role { Name = dto.RoleName });
                if (!create.Succeeded) return BadRequest(create.Errors);
            }

            // Writes a row in AspNetUserRoles
            var res = await _users.AddToRoleAsync(user, dto.RoleName);
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "User added to role", user.Id, dto.RoleName });
        }


        /// <summary>
        /// Lists roles for a user: SELECT from AspNetUserRoles + AspNetRoles.
        /// </summary>
        [HttpGet("users/{userId:long}/roles")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> GetUserRoles(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var roles = await _users.GetRolesAsync(user);
            return Ok(roles);
        }

        // ============================================================
        // 4) USER CLAIMS  ->  AspNetUserClaims
        // ============================================================

        /// <summary>
        /// Adds a claim directly to the user: INSERT into AspNetUserClaims.
        /// Useful for your Module+Action permissions (e.g., ("Users","Read")).
        /// </summary>
        [HttpPost("users/{userId:long}/claims")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> AddUserClaim(long userId, [FromBody] AddUserClaimDto dto)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            // Writes a row in AspNetUserClaims
            var res = await _users.AddClaimAsync(user, new Claim(dto.Type, dto.Value));
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "User claim added", user.Id, dto.Type, dto.Value });
        }

        /// <summary>
        /// Lists user claims: SELECT from AspNetUserClaims.
        /// </summary>
        [HttpGet("users/{userId:long}/claims")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> GetUserClaims(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var claims = await _users.GetClaimsAsync(user);
            return Ok(claims.Select(c => new { c.Type, c.Value }));
        }

        // ============================================================
        // 5) ROLE CLAIMS  ->  AspNetRoleClaims
        // ============================================================

        /// <summary>
        /// Adds a claim to a role: INSERT into AspNetRoleClaims.
        /// Users in that role receive these claims when you include roles in your JWT.
        /// </summary>
        [HttpPost("roles/{roleName}/claims")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> AddRoleClaim(string roleName, [FromBody] AddRoleClaimDto dto)
        {
            var role = await _roles.FindByNameAsync(roleName);
            if (role is null) return NotFound("Role not found");

            // Writes a row in AspNetRoleClaims
            var res = await _roles.AddClaimAsync(role, new Claim(dto.Type, dto.Value));
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "Role claim added", role.Name, dto.Type, dto.Value });
        }

        /// <summary>
        /// Lists role claims: SELECT from AspNetRoleClaims.
        /// </summary>
        [HttpGet("roles/{roleName}/claims")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> GetRoleClaims(string roleName)
        {
            var role = await _roles.FindByNameAsync(roleName);
            if (role is null) return NotFound("Role not found");

            var claims = await _roles.GetClaimsAsync(role);
            return Ok(claims.Select(c => new { c.Type, c.Value }));
        }

        // ============================================================
        // 6) EXTERNAL LOGINS  ->  AspNetUserLogins
        // ============================================================

        /// <summary>
        /// Adds an external login for a user: INSERT into AspNetUserLogins.
        /// This simulates having signed in with Google/Facebook/etc.
        /// </summary>
        [HttpPost("users/{userId:long}/external-login")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> AddExternalLogin(long userId, [FromBody] ExternalLoginDto dto)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var info = new UserLoginInfo(dto.Provider, dto.ProviderKey, dto.DisplayName);

            // Writes a row in AspNetUserLogins
            var res = await _users.AddLoginAsync(user, info);
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "External login added", user.Id, dto.Provider, dto.ProviderKey });
        }

        /// <summary>
        /// Lists external logins for a user: SELECT from AspNetUserLogins.
        /// </summary>
        [HttpGet("users/{userId:long}/external-logins")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> GetExternalLogins(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var logins = await _users.GetLoginsAsync(user);
            return Ok(logins.Select(l => new { l.LoginProvider, l.ProviderKey, l.ProviderDisplayName }));
        }

        // ============================================================
        // 7) USER TOKENS  ->  AspNetUserTokens
        // ============================================================
        // Identity uses this table for things like authenticator keys and token providers.
        // You can ALSO store refresh tokens here (LoginProvider/Name/Value).

        /// <summary>
        /// Saves a refresh token for a user: INSERT/UPDATE in AspNetUserTokens.
        /// </summary>
        [HttpPost("users/{userId:long}/refresh-token")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> SaveRefreshToken(long userId, [FromBody] SaveRefreshTokenDto dto)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            // Writes or updates a row in AspNetUserTokens
            var res = await _users.SetAuthenticationTokenAsync(user, "JWT", "RefreshToken", dto.RefreshToken);
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "Refresh token saved" });
        }

        /// <summary>
        /// Reads the refresh token from AspNetUserTokens (if present).
        /// </summary>
        [HttpGet("users/{userId:long}/refresh-token")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> GetRefreshToken(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var token = await _users.GetAuthenticationTokenAsync(user, "JWT", "RefreshToken");
            return Ok(new { refreshToken = token });
        }

        /// <summary>
        /// Exchanges a refresh token for a new access token.
        /// Validates value against AspNetUserTokens, then returns a new JWT.
        /// </summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> ExchangeRefreshToken([FromBody] ExchangeRefreshTokenDto dto)
        {
            var user = await _users.FindByEmailAsync(dto.Email);
            if (user is null) return Unauthorized();

            var stored = await _users.GetAuthenticationTokenAsync(user, "JWT", "RefreshToken");
            if (string.IsNullOrWhiteSpace(stored) || !string.Equals(stored, dto.RefreshToken, StringComparison.Ordinal))
                return Unauthorized();

            // (Optional) rotate token:
            // var newRefresh = Guid.NewGuid().ToString("N");
            // await _users.SetAuthenticationTokenAsync(user, "JWT", "RefreshToken", newRefresh);

            var accessToken = await _tokens.CreateTokenAsync(user);
            return Ok(new
            {
                accessToken
                // , refreshToken = newRefresh
            });
        }

        /// <summary>
        /// Revokes the saved refresh token: DELETE row from AspNetUserTokens.
        /// </summary>
        [HttpDelete("users/{userId:long}/refresh-token")]
        [Authorize(Policy = "UsersUpdate")]
        public async Task<IActionResult> RevokeRefreshToken(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            // Removes the "JWT/RefreshToken" row from AspNetUserTokens
            var res = await _users.RemoveAuthenticationTokenAsync(user, "JWT", "RefreshToken");
            if (!res.Succeeded) return BadRequest(res.Errors);

            return Ok(new { message = "Refresh token revoked" });
        }

        // ============================================================
        // 8) QUICK DEBUG SNAPSHOT (what does Identity resolve for a user?)
        // ============================================================

        /// <summary>
        /// Consolidated view: shows roles, user-claims, role-claims, external logins, and stored tokens.
        /// </summary>
        [HttpGet("users/{userId:long}/debug")]
        [Authorize(Policy = "UsersRead")]
        public async Task<IActionResult> DebugUser(long userId)
        {
            var user = await _users.FindByIdAsync(userId.ToString());
            if (user is null) return NotFound("User not found");

            var roles = await _users.GetRolesAsync(user);
            var userClaims = await _users.GetClaimsAsync(user);
            var logins = await _users.GetLoginsAsync(user);

            // Collect role claims (AspNetRoleClaims) the user will inherit via roles
            var roleClaims = new List<Claim>();
            foreach (var roleName in roles)
            {
                var role = await _roles.FindByNameAsync(roleName);
                if (role != null)
                {
                    var claims = await _roles.GetClaimsAsync(role);
                    roleClaims.AddRange(claims);
                }
            }

            var savedRefreshToken = await _users.GetAuthenticationTokenAsync(user, "JWT", "RefreshToken");

            return Ok(new
            {
                user = new { user.Id, user.Email, user.UserName },
                roles,                                      // AspNetUserRoles + AspNetRoles
                userClaims = userClaims.Select(c => new { c.Type, c.Value }),        // AspNetUserClaims
                roleClaims = roleClaims.Select(c => new { c.Type, c.Value }),        // AspNetRoleClaims
                externalLogins = logins.Select(l => new { l.LoginProvider, l.ProviderKey, l.ProviderDisplayName }), // AspNetUserLogins
                userTokens = new { RefreshToken = savedRefreshToken }                // AspNetUserTokens
            });
        }
    }
}
