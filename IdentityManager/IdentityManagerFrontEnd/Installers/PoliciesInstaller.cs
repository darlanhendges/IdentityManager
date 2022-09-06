using IdentityManagerFrontEnd.Authorize;
using Microsoft.AspNetCore.Authorization;

namespace IdentityManagerFrontEnd.Installers
{
    public class PoliciesInstaller
    {
        public static void Install(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy(SD.PolicyAdmin, policy => policy.RequireRole(SD.RoleAdmin));
                options.AddPolicy(SD.PolicyUserAndAdmin, policy => policy.RequireRole(SD.RoleAdmin).RequireRole(SD.RoleUser));
                options.AddPolicy(SD.PolicyAdmin_CreateAccess, policy => policy.RequireRole(SD.RoleAdmin).RequireClaim(SD.ClaimCreate, "True"));
                options.AddPolicy(SD.PolicyAdmin_Create_Edit_DeleteAccess, policy => policy.RequireRole(SD.RoleAdmin).RequireClaim(SD.ClaimCreate, "True")
                .RequireClaim(SD.ClaimEdit, "True")
                .RequireClaim(SD.ClaimEdit, "True"));

                options.AddPolicy(SD.PolicyAdmin_Create_Edit_DeleteAccess_OR_SuperAdmin,
                    policy => policy.RequireAssertion(context => AuthorizeAdminWithClaimsOrSuperAdmin(context)));
                options.AddPolicy(SD.PolicyOnlySuperAdminChecker, policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
                options.AddPolicy(SD.PolicyAdminWithMoreThan1000Days, policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
                options.AddPolicy(SD.PolicyFirstNameAuth, policy => policy.Requirements.Add(new FirstNameAuthRequirement("billy")));
            });
        }
        private static bool AuthorizeAdminWithClaimsOrSuperAdmin(AuthorizationHandlerContext context)
        {
            return (context.User.IsInRole(SD.RoleAdmin) && context.User.HasClaim(c => c.Type == SD.ClaimCreate && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == SD.ClaimEdit && c.Value == "True")
                        && context.User.HasClaim(c => c.Type == SD.ClaimDelete && c.Value == "True")
                    ) || context.User.IsInRole(SD.RoleSuperAdmin);
        }
    }
}
