using System.Security.Claims;

namespace IdentityManagerFrontEnd
{
    public static class SD
    {
        public const string Success = "Success";
        public const string Error = "Error";

        public const string ClaimCreate = "Create";
        public const string ClaimEdit = "Edit";
        public const string ClaimDelete = "Delete";

        public static List<Claim> ClaimsList = new List<Claim>()
        {
            new Claim(ClaimCreate,ClaimCreate),
            new Claim(ClaimEdit,ClaimEdit),
            new Claim(ClaimDelete,ClaimEdit)
        };

        public const string PolicyAdmin = "Admin";
        public const string PolicyUserAndAdmin = "UserAndAdmin";
        public const string PolicyAdmin_CreateAccess = "Admin_CreateAccess";
        public const string PolicyAdmin_Create_Edit_DeleteAccess = "Admin_Create_Edit_DeleteAccess";
        public const string PolicyAdmin_Create_Edit_DeleteAccess_OR_SuperAdmin = "Admin_Create_Edit_DeleteAccess_OR_SuperAdmin";
        public const string PolicyOnlySuperAdminChecker = "OnlySuperAdminChecker";
        public const string PolicyAdminWithMoreThan1000Days = "AdminWithMoreThan1000Days";
        public const string PolicyFirstNameAuth = "FirstNameAuth";

        public const string RoleAdmin = "Admin";
        public const string RoleUser = "User";
        public const string RoleSuperAdmin = "SuperAdmin";
    }
}
