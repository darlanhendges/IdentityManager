using Microsoft.AspNetCore.Mvc;

namespace IdentityManagerFrontEnd.Controllers
{
    public class RolesController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
