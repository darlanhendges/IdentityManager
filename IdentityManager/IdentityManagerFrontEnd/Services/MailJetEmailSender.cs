using Mailjet.Client;
using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Identity.UI.Services;
using Newtonsoft.Json.Linq;

namespace IdentityManagerFrontEnd.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly MailJetOptions _options;


        public MailJetEmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
            _options = _configuration.GetSection("MailJet").Get<MailJetOptions>();
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            return Task.CompletedTask;
        }
    }
}
