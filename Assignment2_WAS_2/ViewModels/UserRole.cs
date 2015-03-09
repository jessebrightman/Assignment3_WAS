using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Assignment2_WAS_2.ViewModels
{
    public class UserRole
    {
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Display(Name = "Role Name")]
        public string RoleName { get; set; }
    }
}