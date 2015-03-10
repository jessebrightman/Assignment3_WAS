using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace Assignment2_WAS_2.ViewModels
{
    public class Message
    {
        [Required(ErrorMessage = "Your email address is required.")]
        [RegularExpression(@"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*", ErrorMessage = "Please enter a valid email address.")]
        public string Sender { get; set; }

        [Required(ErrorMessage = "An email subject is required.")]
        [StringLength(200, MinimumLength = 1)]
        public string Subject { get; set; }

        [Required(ErrorMessage = "A message is required.")]
        [StringLength(5000, MinimumLength = 1)]
        public string Body { get; set; }

        public Message() { }
        public Message(string sender, string subject, string body)
        {
            Sender = sender;
            Subject = subject;
            Body = body;
        }
    }
}
