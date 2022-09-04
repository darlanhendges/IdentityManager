using IdentityManagerFrontEnd.Data;
using IdentityManagerFrontEnd.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagerFrontEnd.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            var userList = await _db.ApplicationUser.ToListAsync();
            var roles = await _db.Roles.ToListAsync();
            var userRoles = await _db.UserRoles.ToListAsync();

            foreach (var user in userList)
            {
                var role = userRoles.FirstOrDefault(r => r.UserId.Equals(user.Id));
                if (role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.First(r => r.Id.Equals(role.RoleId)).Name;
                }
            }

            return View(userList);
        }
    }
}
