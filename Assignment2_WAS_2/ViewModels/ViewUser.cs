using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Assignment2_WAS_2.ViewModels
{
    public class ViewUser
    {
        [Display(Name = "User Name")]
        public string UserName { get; set; }
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string Role { get; set; }

        public ViewUser(string userName, string address, string city, string state, string country, string role)
        {
            UserName = userName;
            Address = address;
            City = city;
            State = state;
            Country = country;
            Role = role;
        }
    }
}