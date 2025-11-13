using Microsoft.AspNetCore.Authorization;

namespace IdentityUserImplementation.PolicyHandler
{
    /// <summary>
    /// AuthorizePolicyHandler
    /// </summary>
    public class AuthorizePolicyHandler : AuthorizationHandler<AuthorizePolicyRequirement>
    {
        private readonly ILogger<AuthorizePolicyHandler> _logger;

        // Inject ILogger into the handler constructor
        public AuthorizePolicyHandler(ILogger<AuthorizePolicyHandler> logger)
        {
            _logger = logger;
        }
        /// <summary>
        /// HandleRequirementAsync
        /// </summary>
        /// <param name="context"></param>
        /// <param name="requirement"></param>
        /// <returns></returns>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AuthorizePolicyRequirement requirement)
        {
            // Log the policies being checked
            _logger.LogInformation("Checking policies: {Policies}", string.Join(", ", requirement.Policies));

            // Loop through each policy and check if the user satisfies it
            foreach (var policy in requirement.Policies)
            {
                // Log the current policy being checked
                _logger.LogInformation("Checking policy: {Policy}", policy);
                var userClaim = context.User.Claims.FirstOrDefault().Value;
                _logger.LogInformation("Checking policy: {userClaim}", userClaim);
                // Check if the user has the required claim for this exact policy
                var hasValidClaim = context.User.Claims.Any(c =>
                    StaticAuthValues.GetModules().Contains(c.Type) &&
                    StaticAuthValues.GetActions().Contains(c.Value) &&
                    policy == $"{c.Type}{c.Value}" // Ensure that the policy matches the type-value combination exactly
                );

                // Log whether the user has a valid claim
                if (hasValidClaim)
                {
                    _logger.LogInformation("User has valid claim for policy: {Policy}", policy);
                    context.Succeed(requirement); // User has the claim for this policy
                    return Task.CompletedTask;
                }
                else
                {
                    _logger.LogWarning("User does not have valid claim for policy: {Policy}", policy);
                }
            }

            // If no valid claims are found for any of the policies, fail the requirement and deny access
            _logger.LogWarning("User does not have any valid claims for the required policies.");
            context.Fail();  // Mark the requirement as failed
            return Task.CompletedTask;

        }
    }
}
