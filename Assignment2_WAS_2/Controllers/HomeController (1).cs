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

namespace Assignment2_WAS_2.Controllers
{
    public class HomeController : Controller
    {
        SecureLoginEntities db = new SecureLoginEntities();

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
                if (identityUser != null)
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
            ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Please Register before Logging In.</div>";
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
            var userStore = new UserStore<IdentityUser>();
            var manager = new UserManager<IdentityUser>(userStore);
            var identityUser = new IdentityUser()
            {
                UserName = newUser.UserName,
                Email = newUser.Email,
                PhoneNumber = newUser.PhoneNumber
            };

            IdentityResult result = manager.Create(identityUser, newUser.Password);

            if (result.Succeeded)
            {
                var authenticationManager
                                  = HttpContext.Request.GetOwinContext().Authentication;
                var userIdentity = manager.CreateIdentity(identityUser,
                                           DefaultAuthenticationTypes.ApplicationCookie);
                authenticationManager.SignIn(new AuthenticationProperties() { },
                                             userIdentity);

                MyUser myUser = new MyUser();

                myUser.myUser1 = newUser.UserName;
                myUser.myEmail = newUser.Email;
                myUser.myAddress = newUser.Address;
                myUser.phone = newUser.PhoneNumber;
                myUser.city = newUser.City;
                myUser.province = newUser.State;
                myUser.country = newUser.Country;

                db.MyUsers.Add(myUser);

                db.SaveChanges();
                ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have been Registered.  Please Login.</div>";
            }
            else 
            {
                foreach (var error in result.Errors)
                {
                    ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Registration failed. " + error + ". Please Register again.</div>";
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
            try
            {
                db.AspNetRoles.Add(role);
                db.SaveChanges();
                ViewBag.Message = "<div class='alert alert-success form-group' role='alert'>You have successfully added the Role.</div>";
            }
            catch (SqlException e)
            {
                string error = e.ToString();
                ViewBag.Message = "<div class='alert alert-danger form-group' role='alert'>Role creation failed. " + error + ". Please try again.</div>";
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
        public ActionResult ModifyUserRole(string userName, string roleName)
        {
            AspNetUser user = db.AspNetUsers
                             .Where(u => u.UserName == userName).FirstOrDefault();
            AspNetRole role = db.AspNetRoles
                             .Where(r => r.Name == roleName).FirstOrDefault();

            user.AspNetRoles.Add(role);
            db.SaveChanges();
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
    }
}

