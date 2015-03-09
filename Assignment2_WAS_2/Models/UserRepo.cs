using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Assignment2_WAS_2.ViewModels;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity.Owin;

namespace Assignment2_WAS_2.Models
{
    public class UserRepo
    {
        SecureLoginEntities db = new SecureLoginEntities();
        public IEnumerable<ViewUser> GetViewUsers()
        {
            var query = (from u in db.AspNetUsers
                         from r in u.AspNetRoles
                         from m in db.MyUsers
                         where u.Id.Contains(r.Id)
                         where u.UserName == m.myUser1
                         select new
                         {
                             UserName = u.UserName,
                             Address = m.myAddress,
                             City = m.city,
                             State = m.province,
                             Country = m.country,
                             Role = r.Name
                         }).ToList();

            List<ViewUser> users = new List<ViewUser>();
            foreach(var user in query)
            {
                users.Add(new ViewUser(user.UserName, user.Address, user.City, user.State, user.Country, user.Role));
            }
            return users;
        }

        public bool SaveMyUser(RegisteredUser newUser)
        {
            MyUser thisUser = new MyUser();

            thisUser.myUser1 = newUser.UserName;
            thisUser.myEmail = newUser.Email;
            thisUser.myAddress = newUser.Address;
            thisUser.phone = newUser.PhoneNumber;
            thisUser.city = newUser.City;
            thisUser.province = newUser.State;
            thisUser.country = newUser.Country;

            db.MyUsers.Add(thisUser);

            db.SaveChanges();
            return true;
            
        }

        public bool ValidLogin(Login login)
        {
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 10, 0),
                MaxFailedAccessAttemptsBeforeLockout = 3
            };
            var user = userManager.FindByName(login.UserName);

            if (user == null)
                return false;

            // User is locked out.
            if (userManager.SupportsUserLockout && userManager.IsLockedOut(user.Id))
                return false;

            // Validated user was locked out but now can be reset.
            if (userManager.CheckPassword(user, login.Password)
                && userManager.IsEmailConfirmed(user.Id))
            {
                if (userManager.SupportsUserLockout
                 && userManager.GetAccessFailedCount(user.Id) > 0)
                {
                    userManager.ResetAccessFailedCount(user.Id);
                }
            }
            // Login is invalid so increment failed attempts.
            else
            {
                bool lockoutEnabled = userManager.GetLockoutEnabled(user.Id);
                if (userManager.SupportsUserLockout && userManager.GetLockoutEnabled(user.Id))
                {
                    userManager.AccessFailed(user.Id);
                    return false;
                }
            }
            return true;
        }

        public const string EMAIL_CONFIRMATION = "EmailConfirmation";
        public const string PASSWORD_RESET = "ResetPassword";
        public bool CreateTokenProvider(UserManager<IdentityUser> manager, string tokenType)
        {
            var provider = new DpapiDataProtectionProvider("MyApplicaitonName");
            manager.UserTokenProvider = new DataProtectorTokenProvider<IdentityUser>(
            provider.Create(tokenType));
            return true;
        }
    }
}