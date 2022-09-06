using System.Security.Claims;

namespace IdentityManagerFrontEnd
{
    public static class SD
    {
        public const string Success = "Success";
        public const string Error = "Error";

        public static List<Claim> ClaimsList = new List<Claim>()
        {
            new Claim("Create","Create"),
            new Claim("Edit","Edit"),
            new Claim("Delete","Delete")
        };
    }
}
