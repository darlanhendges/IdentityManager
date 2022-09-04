using IdentityManagerFrontEnd.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagerFrontEnd.Controllers
{
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;


        public RolesController(ApplicationDbContext db, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            var roles = await _db.Roles.ToListAsync();
            return View(roles);
        }

        [HttpGet]
        public async Task<IActionResult> Upsert(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                var obj = await _db.RoleClaims.FirstOrDefaultAsync(r => r.Id.Equals(id));
                return View(obj);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole role)
        {
            if (await _roleManager.RoleExistsAsync(role.Name))
            {
                TempData[SD.Error] = "Role already exists.";
                return RedirectToAction(nameof(Index));

            }

            if (string.IsNullOrEmpty(role.Id))
            {
                await _roleManager.CreateAsync(new IdentityRole(role.Name));
                TempData[SD.Success] = "Role created successfully.";

            }
            else
            {
                var roleFromDb = await _db.Roles.FirstOrDefaultAsync(r => r.Id.Equals(role.Id));
                if (roleFromDb == null)
                {
                    TempData[SD.Error] = "Role not found.";
                    return RedirectToAction(nameof(Index));

                }

                roleFromDb.Name = role.Name;
                roleFromDb.NormalizedName = role.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(roleFromDb);

                TempData[SD.Success] = "Role update successfully.";
            }

            return RedirectToAction(nameof(Index));
        }
    }
}
