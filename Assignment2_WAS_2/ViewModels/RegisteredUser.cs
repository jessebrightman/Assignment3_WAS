using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Assignment2_WAS_2.ViewModels
{
    public class RegisteredUser
    {
        [Required]
        [Display(Name = "User Name")]
        public string UserName { get; set; }

        [Required]
        [RegularExpression(@"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$",
        ErrorMessage = "This is not a valid email address.")]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [RegularExpression(@"^(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}$", ErrorMessage = "This is not a valid phone number.")]
        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; }

        [Required]
        [StringLength(60, MinimumLength = 3, ErrorMessage = "This is not a valid address.")]
        [Display(Name = "Address")]
        public string Address { get; set; }

        [Required]
        [StringLength(60, MinimumLength = 2, ErrorMessage = "This is not a valid city.")]
        [Display(Name = "City")]
        public string City { get; set; }

        [Required]
        [StringLength(60, MinimumLength = 2, ErrorMessage = "This is not a valid state/province.")]
        [Display(Name = "State")]
        public string State { get; set; }

        [Required]
        [StringLength(60, MinimumLength = 2, ErrorMessage = "This is not a valid country.")]
        [Display(Name = "Country")]
        public string Country { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password Confirm")]
        [Compare("Password", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

}