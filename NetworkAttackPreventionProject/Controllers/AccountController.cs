using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using NetworkAttackPreventionProject.Models;
using NetworkAttackPreventionProject.Utilities.Helper;
using NetworkAttackPreventionProject.ViewModels.Authentication;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using static NetworkAttackPreventionProject.Utilities.Helper.Helper;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;


namespace NetworkAttackPreventionProject.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        private IConfiguration _configuration { get; }

        public AccountController(UserManager<ApplicationUser> userManager,
                                      SignInManager<ApplicationUser> signInManager,
                                      RoleManager<IdentityRole> roleManager,
                                      IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterVM register)
        {
            if (!ModelState.IsValid) return View(register);

            ApplicationUser user = new ApplicationUser()
            {
                UserName = register.Username,
                Email = register.Email

            };

            ApplicationUser userEmail = await _userManager.FindByEmailAsync(user.Email);

            if (userEmail != null)
            {
                ModelState.AddModelError(string.Empty, "Bu e-poçtla qeydiyyatdan keçə bilməzsiniz, çünki o, artıq mövcuddur");
                return View();
            }



            var identityResult = await _userManager.CreateAsync(user, register.Password);


            if (!identityResult.Succeeded)
            {
                foreach (var error in identityResult.Errors)
                {
                    ModelState.AddModelError(String.Empty, error.Description);
                }
                return View(register);
            }

            await _userManager.AddToRoleAsync(user, UserRoles.Client.ToString());

            await _signInManager.SignInAsync(user, isPersistent: false);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Email", new { token, email = register.Email }, Request.Scheme);
            EmailHelper emailHelper = new EmailHelper();

            bool emailResponse = emailHelper.SendEmail(register.Email, confirmationLink);

            if (emailResponse)
            {

                return RedirectToAction("SuccesSending", "Account");
            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult Login()
        {
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginVM loginVM, string ReturnUrl)
        {
            if (!ModelState.IsValid) return View();

            ApplicationUser user = await _userManager.FindByEmailAsync(loginVM.Email);

            if (user == null)
            {
                ModelState.AddModelError(String.Empty, "E-posta veya şifre yanlışdır");
                return View(loginVM);
            }

            SignInResult signInResult = await _signInManager.PasswordSignInAsync(user, loginVM.Password, loginVM.RememberMe, true);

            bool emailStatus = await _userManager.IsEmailConfirmedAsync(user);
            if (emailStatus == false)
            {
                ModelState.AddModelError(nameof(loginVM.Email), "E-poçt təsdiqlənməyib, əvvəlcə onu təsdiqləyin");
            }

            if (signInResult.IsLockedOut)
            {
                ModelState.AddModelError(String.Empty, "Zəhmət olmasa bir neçə dəqiqə gözləyin");
                return View(loginVM);
            }

            if (!signInResult.Succeeded)
            {
                ModelState.AddModelError(String.Empty, "E-posta veya şifre yanlışdır");
                return View(loginVM);
            }

            if (ReturnUrl != null)
            {
                return Redirect(ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null)
            {
                ModelState.AddModelError(string.Empty, "Əməliyyat yanlışdır");
                return View();
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM resetVM)
        {
            if (!ModelState.IsValid) return View(resetVM);

            var user = await _userManager.FindByEmailAsync(resetVM.Email);

            if (user == null)
                RedirectToAction("ResetPasswordConfirmation");

            var result = await _userManager.ResetPasswordAsync(user, resetVM.Token, resetVM.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View();
            }

            return RedirectToAction("Login", "Account");
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordVM forgetVM)
        {
            if (!ModelState.IsValid) return View(forgetVM);
            var user = await _userManager.FindByEmailAsync(forgetVM.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Hesabınız yanlışdır");
                return View();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var confirmationLink = Url.Action("ResetPassword", "Account", new { token, email = forgetVM.Email }, Request.Scheme);
            EmailHelper emailHelper = new EmailHelper();
            bool emailResponse = emailHelper.SendEmail(forgetVM.Email, confirmationLink);


            if (emailResponse)
            {
                ModelState.AddModelError(string.Empty, "Uğurla başa çatdı. ");
                return RedirectToAction("ForgotPasswordConfirmation");
            }

            return View();
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        public IActionResult SuccesSending()
        {
            return View();
        }

        #region CreateRole
        //public async Task CreateRole()
        //{
        //    foreach (var role in Enum.GetValues(typeof(UserRoles)))
        //    {
        //        if (!await _roleManager.RoleExistsAsync(role.ToString()))
        //        {
        //            await _roleManager.CreateAsync(new IdentityRole { Name = role.ToString() });
        //        }
        //    }
        //}
        #endregion


    }
}
