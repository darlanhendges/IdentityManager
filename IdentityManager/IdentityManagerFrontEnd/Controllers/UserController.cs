using IdentityManagerFrontEnd.Data;
using IdentityManagerFrontEnd.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
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

        public async Task<IActionResult> Edit(string userId)
        {
            var objFromDb = await _db.ApplicationUser.FirstOrDefaultAsync(u => u.Id == userId);
            if (objFromDb == null)
            {
                return NotFound();
            }

            var userRole = await  _db.UserRoles.ToListAsync();
            var roles = await _db.Roles.ToListAsync();
            var role =  userRole.FirstOrDefault(u => u.UserId == objFromDb.Id);

            if (role != null)
            {
                objFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }
          
            objFromDb.RoleList = _db.Roles.Select(u => new SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });

            return View(objFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (ModelState.IsValid)
            {
                var objFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
                if (objFromDb == null)
                {
                    return NotFound();
                }
                var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);
                if (userRole != null)
                {
                    var previousRoleName = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    await _userManager.RemoveFromRoleAsync(objFromDb, previousRoleName);
                }

                await _userManager.AddToRoleAsync(objFromDb, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                objFromDb.Name = user.Name;

                _db.SaveChanges();
                TempData[SD.Success] = "User has been edited successfully.";

                return RedirectToAction(nameof(Index));
            }


            user.RoleList = _db.Roles.Select(u => new SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });

            return View(user);
        }
    }
}
