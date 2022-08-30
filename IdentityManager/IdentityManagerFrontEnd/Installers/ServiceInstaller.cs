using IdentityManagerFrontEnd.Data;
using IdentityManagerFrontEnd.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityManagerFrontEnd.Installers
{
    public class ServiceInstaller
    {
        public static void Install(IServiceCollection services)
        {
            services.AddTransient<IEmailSender, MailJetEmailSender>();
        }
    }
}
