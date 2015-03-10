using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Assignment2_WAS_2.ViewModels
{
    public class UserRole
    {
        [Required(ErrorMessage = "A valid User Name is required.")]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "A valid Role is required.")]
        [Display(Name = "Role Name")]
        public string RoleName { get; set; }
    }
}