using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly ILogger<AccountsController> _logger;
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _cognitoUserPool;

        public AccountsController(
            ILogger<AccountsController> logger, 
            SignInManager<CognitoUser> signInManager, 
            UserManager<CognitoUser> userManager, 
            CognitoUserPool cognitoUserPool)
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
            _cognitoUserPool = cognitoUserPool;
        }

        public IActionResult SignUp()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _cognitoUserPool.GetUser(model.Email);

                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);

                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
            }

            return View();
        }

        public IActionResult Confirm()
        {
            var model = new ConfirmModel();

            return View(model);
        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> Confirm_Post(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email was not found");
                    return View(model);
                }

                var result = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true);

                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }

                    return View(model);
                }
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                    ModelState.AddModelError("LoginError", "User not found");
            }

            return View("Login", model);
        }
    }
}