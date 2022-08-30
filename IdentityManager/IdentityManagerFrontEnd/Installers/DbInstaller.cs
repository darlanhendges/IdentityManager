using IdentityManagerFrontEnd.Data;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagerFrontEnd.Installers
{
    public class DbInstaller
    {
        public static void Install(IServiceCollection services, string connectionString)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(connectionString);
            });
        }
    }
}
