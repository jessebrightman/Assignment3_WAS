using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Assignment2_WAS_2.ViewModels;
using Assignment2_WAS_2.Models;
using System.Data.SqlClient;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity.Owin;
using Assignment2_WAS_2.BusinessLogic;

namespace Assignment2_WAS_2.Controllers
{
    public class HomeController : Controller
    {
        SecureLoginEntities db = new SecureLoginEntities();
        UserRepo createtoken = new UserRepo();
        public const string EMAIL_CONFIRMATION = "EmailConfirmation";
        public const string PASSWORD_RESET = "ResetPassword";

        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Index(Login login)
        {
            // UserStore and UserManager manages data retreival.
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            IdentityUser identityUser = manager.Find(login.UserName,
                                                             login.Password);

            if (ModelState.IsValid)
            {
                UserRepo validLogin = new UserRepo();
                if (validLogin.ValidLogin(login)) 
                {
                    IAuthenticationManager authenticationManager
                                           = HttpContext.GetOwinContext().Authentication;
                    authenticationManager
                   .SignOut(DefaultAuthenticationTypes.ExternalCookie);

                    var identity = new ClaimsIdentity(new[] {
                                            new Claim(ClaimTypes.Name, login.UserName),
                                        },
                                        DefaultAuthenticationTypes.ApplicationCookie,
                                        ClaimTypes.Name, ClaimTypes.Role);
                    // SignIn() accepts ClaimsIdentity and issues logged in cookie. 
                    authenticationManager.SignIn(new AuthenticationProperties
                    {
                        IsPersistent = false
                    }, identity);
                    return RedirectToAction("Welcome", "Home");
                }
            }
            else 
            {
                ViewBag.Message = "<div class='alert alert-danger form-group'   role='alert'>Please Register before Logging In.</div>";
            }
            
            return View();
        }
        [HttpGet]
        public ActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisteredUser newUser)
        {
            if (ModelState.IsValid)
            {
                CaptchaHelper captchaHelper = new CaptchaHelper();
                string captchaResponse = captchaHelper.CheckRecaptcha();
                ViewBag.CaptchaResponse = captchaResponse;

                if (newUser != null)
                {
                    var userStore = new UserStore<IdentityUser>();
                    UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore)
                    {
                        UserLockoutEnabledByDefault = true,
                        DefaultAccountLockoutTimeSpan = new TimeSpan(0, 10, 0),
                        MaxFailedAccessAttemptsBeforeLockout = 3
                    };

                    var identityUser = new IdentityUser()
                    {
                        UserName = newUser.UserName,
                        Email = newUser.Email,
                        PhoneNumber = newUser.PhoneNumber
                    };

                    IdentityResult result = manager.Create(identityUser, newUser.Password);
                    UserRepo viewUserRepo = new UserRepo();
                    viewUserRepo.SaveMyUser(newUser);

                    if (result.Succeeded && viewUserRepo != null)
                    {       
                        createtoken.CreateTokenProvider(manager, EMAIL_CONFIRMATION);
                        var code = manager.GenerateEmailConfirmationToken(identityUser.Id);
                        var callbackUrl = Url.Action("ConfirmEmail", "Home",
                                                        new { userId = identityUser.Id, code = code },
                                                            protocol: Request.Url.Scheme);

                        if (code != null)
                        {
                            MailHelper mailer = new MailHelper();
                            mailer.SendEmail(callbackUrl, newUser);
                        }

                        ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have been Registered.  Please check your inbox for our email to confirm your registration.</div>";
                    }
                    else
                    {
                        foreach (var error in result.Errors)
                        {
                            ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Registration failed. " + error + ". Please Register again.</div>";
                        }
                    }
                }
            }
            return View();
        }
        [Authorize]
        public ActionResult Welcome()
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public ActionResult CreateRole()
        {
            return View();
        }

        [HttpPost]
        public ActionResult CreateRole(AspNetRole role)
        {
            if (db.AspNetRoles.Find(role.Id)==null)
                try
                {
                    db.AspNetRoles.Add(role);
                    db.SaveChanges();
                    ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have successfully added the " + role.Name + " Role.</div>";
                }
                catch (Exception e)
                {
                    string error = e.ToString();
                    ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Role creation failed. " + error + ". Please try again.</div>";
                }
            else
            {
                ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Role creation failed. " + role.Name + " already exists.</div>";
            }
            return View();
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public ActionResult ModifyUserRole()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ModifyUserRole(string userName, string roleName, string button)
        {
            
            try
            {
                if (button == "Create")
                {
                    AspNetUser user = db.AspNetUsers
                                     .Where(u => u.UserName == userName).FirstOrDefault();
                    AspNetRole role = db.AspNetRoles
                                     .Where(r => r.Name == roleName).FirstOrDefault();
                    if (user.AspNetRoles.Contains(role) != true)
                    {
                        user.AspNetRoles.Add(role);
                        db.SaveChanges();
                        ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have successfully added " + userName + " to the " + roleName + " Role.</div>";
                    }
                    else
                    {
                        ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Modify User Role failed. " + userName + " already belongs to the " + roleName + " Role.</div>";
                    }
                }
                if (button == "Delete")
                {
                    AspNetUser user = db.AspNetUsers
                                     .Where(u => u.UserName == userName).FirstOrDefault();
                    AspNetRole role = db.AspNetRoles
                                     .Where(r => r.Name == roleName).FirstOrDefault();
                    if (user.AspNetRoles.Contains(role) == true)
                    {
                        user.AspNetRoles.Remove(role);
                        db.SaveChanges();
                        ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have successfully deleted " + userName + " from the " + roleName + " Role.</div>";
                    }
                    else
                    {
                        ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Modify User Role failed. " + userName + " does not belong to the " + roleName + " Role.</div>";
                    }
                }
            }
            catch
            {
                ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Failed to delete " + userName + " from the " + roleName + " Role. Please try again.</div>";
            }
            return View();
        }

        [Authorize(Roles = "Admin, Staff")]
        [HttpGet]
        public ActionResult ViewUsers()
        {
            UserRepo viewUser = new UserRepo();
            return View(viewUser.GetViewUsers());
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        

        public ActionResult ConfirmEmail(string userID, string code)
        {
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            createtoken.CreateTokenProvider(manager, EMAIL_CONFIRMATION);
            try
            {
                IdentityResult result = manager.ConfirmEmail(userID, code);
                if (result.Succeeded)
                    ViewBag.Message = "You are now registered!";
            }
            catch
            {
                ViewBag.Message = "Validation attempt failed!";
            }
            return View();
        }

        [HttpGet]
        public ActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ForgotPassword(string username)
        {
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var search = db.AspNetUsers.Where(u => u.UserName == username).Select(u => new {email = u.Email, userID = u.Id}).First();
            var user = manager.FindById(search.userID);
            createtoken.CreateTokenProvider(manager, PASSWORD_RESET);

            var code = manager.GeneratePasswordResetToken(user.Id);
            var callbackUrl = Url.Action("ResetPassword", "Home",
                                         new { userId = user.Id, code = code },
                                         protocol: Request.Url.Scheme);
            //ViewBag.FakeEmailMessage = "Please reset your password by clicking <a href=\""
            //                         + callbackUrl + "\">here</a>";

            MailHelper mailer = new MailHelper();
            string email = "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>";
            string subject = "Please reset your password.";
            string response = mailer.EmailFromArvixe(
                                       new Email(search.email, subject, email));

            ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>Please check your inbox for our email to reset your password.</div>";
            return View();
        }

        [HttpGet]
        public ActionResult ResetPassword(string userID, string code)
        {
            ViewBag.PasswordToken = code;
            ViewBag.UserID = userID;
            return View();
        }
        [HttpPost]

        public ActionResult ResetPassword(string password, string passwordConfirm,
                                          string passwordToken, string userID)
        {
            if (ModelState.IsValid)
            {
                CaptchaHelper captchaHelper = new CaptchaHelper();
                string captchaResponse = captchaHelper.CheckRecaptcha();
                ViewBag.CaptchaResponse = captchaResponse;

                var userStore = new UserStore<IdentityUser>();
                UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
                var user = manager.FindById(userID);
                createtoken.CreateTokenProvider(manager, PASSWORD_RESET);

                IdentityResult result = manager.ResetPassword(userID, passwordToken, password);
                if (result.Succeeded)
                    ViewBag.Result = "The password has been reset.";
                else
                    ViewBag.Result = "The password has not been reset.";
            }
            return View();
        }

    }
}

