namespace IdentityUserImplementation.Dtos
{
    // ---------------------------
    // DTOs
    // ---------------------------
    public record RegisterDto(string Email, string Password);
    public record LoginDto(string Email, string Password);
    public record RoleDto(string RoleName);
    public record AddUserClaimDto(string Type, string Value);
    public record AddRoleClaimDto(string Type, string Value);
    public record ExternalLoginDto(string Provider, string ProviderKey, string DisplayName);
    public record SaveRefreshTokenDto(string RefreshToken);
    public record ExchangeRefreshTokenDto(string Email, string RefreshToken);
}
