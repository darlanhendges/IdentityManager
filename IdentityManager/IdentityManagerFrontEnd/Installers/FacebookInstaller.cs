using IdentityManagerFrontEnd.Services;

namespace IdentityManagerFrontEnd.Installers
{
    public class FacebookInstaller
    {
        public static void Install(IServiceCollection services, FacebookOptions facebookOptions)
        {

            services.AddAuthentication()
                  .AddFacebook(options =>
                  {
                      options.AppId = facebookOptions.AppId;
                      options.AppSecret = facebookOptions.AppSecret;
                  });
        }
    }
}
