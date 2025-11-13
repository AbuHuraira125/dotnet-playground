using Microsoft.AspNetCore.Authorization;

namespace IdentityUserImplementation.PolicyHandler
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
    public class AuthorizePolicyAttribute : AuthorizeAttribute
    {
        public AuthorizePolicyAttribute(string policy) => Policy = policy;
    }
}
