using IdentityUserImplementation.Domain.UserEntities;
using IdentityUserImplementation.PolicyHandler;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityUserImplementation.Controllers
{
    public class UsersController : BaseController
    {
        private readonly UserManager<AppUser> _users;
        private readonly RoleManager<Role> _roles;

        public UsersController(UserManager<AppUser> users, RoleManager<Role> roles)
        {
            _users = users; _roles = roles;
        }

        [HttpGet]
        [Route("api/users")]
        [AuthorizePolicy("UsersRead")]
        public IActionResult GetUsers() =>
            Ok(_users.Users.Select(u => new { u.Id, u.Email, u.UserName }));

        [HttpGet("api/users/{id:long}")]
        [AuthorizePolicy("UsersRead")]
        public async Task<IActionResult> GetById(long id)
        {
            var u = await _users.FindByIdAsync(id.ToString());
            return u is null ? NotFound() : Ok(new { u.Id, u.Email, u.UserName });
        }

        [HttpPut("api/users/{id:long}")]
        [AuthorizePolicy("UsersUpdate")]
        public async Task<IActionResult> UpdateEmail(long id, [FromBody] string newEmail)
        {
            var u = await _users.FindByIdAsync(id.ToString());
            if (u is null) return NotFound();
            u.Email = newEmail; u.UserName = newEmail;
            var res = await _users.UpdateAsync(u);
            return res.Succeeded ? Ok() : BadRequest(res.Errors);
        }

        [HttpDelete("api/users/{id:long}")]
        [AuthorizePolicy("UsersDelete")]
        public async Task<IActionResult> Delete(long id)
        {
            var u = await _users.FindByIdAsync(id.ToString());
            if (u is null) return NotFound();
            var res = await _users.DeleteAsync(u);
            return res.Succeeded ? Ok() : BadRequest(res.Errors);
        }

        public record AddRoleDto(string RoleName);
        [HttpPost("api/users/{id:long}/roles")]
        [AuthorizePolicy("UsersUpdate")]
        public async Task<IActionResult> AddRole(long id, [FromBody] AddRoleDto dto)
        {
            var u = await _users.FindByIdAsync(id.ToString());
            if (u is null) return NotFound();

            if (!await _roles.RoleExistsAsync(dto.RoleName))
                await _roles.CreateAsync(new Role { Name = dto.RoleName });

            var res = await _users.AddToRoleAsync(u, dto.RoleName);
            return res.Succeeded ? Ok() : BadRequest(res.Errors);
        }

        public record AddClaimDto(string Module, string Action);
        [HttpPost("api/users/{id:long}/claims")]
        [AuthorizePolicy("UsersUpdate")]
        public async Task<IActionResult> AddClaim(long id, [FromBody] AddClaimDto dto)
        {
            if (!StaticAuthValues.GetModules().Contains(dto.Module) ||
                !StaticAuthValues.GetActions().Contains(dto.Action))
                return BadRequest("Invalid Module or Action.");

            var u = await _users.FindByIdAsync(id.ToString());
            if (u is null) return NotFound();

            var res = await _users.AddClaimAsync(u, new Claim(dto.Module, dto.Action));
            return res.Succeeded ? Ok() : BadRequest(res.Errors);
        }
    }
}
