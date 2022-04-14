using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetworkAttackPreventionProject.Models;
using System.Threading.Tasks;

namespace NetworkAttackPreventionProject.Controllers
{
    public class EmailController : Controller
    {
        private UserManager<ApplicationUser> _userManager;
        public EmailController(UserManager<ApplicationUser> usrMgr)
        {
            _userManager = usrMgr;
        }

        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return View("Error");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }
    }
}
