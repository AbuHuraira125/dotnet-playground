using Microsoft.AspNetCore.Authorization;

namespace IdentityUserImplementation.PolicyHandler
{
    /// <summary>
    /// AuthorizePolicyRequirement
    /// </summary>
    public class AuthorizePolicyRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// AuthorizePolicyRequirement
        /// </summary>
        /// <param name="policies"></param>
        public AuthorizePolicyRequirement(string[] policies)
        {
            Policies = policies;
        }
        /// <summary>
        /// Policies
        /// </summary>
        public string[] Policies { get; }
    }
}
