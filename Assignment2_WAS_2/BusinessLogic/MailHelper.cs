using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Web;
using Assignment2_WAS_2.ViewModels;

namespace Assignment2_WAS_2.BusinessLogic
{
    public class MailHelper {
        public const string SUCCESS 
        = "Success! Your email has been sent.  Please allow up to 48 hrs for a reply.";
                                            // Specify where you want this email sent.
                                            // This value may/may not be constant.
                                            // To get started use one of your email 
                                            // addresses.
        public string EmailFromArvixe(Email message) {
            
            string TO = message.Sender;
       
            // Use credentials of the Mail account that you created with the steps above.
            const string FROM        = "support@jesse-brightman.com";
            const string FROM_PWD    = "support";                
            const bool   USE_HTML    = true;

            // Get the mail server obtained in the steps described above.
            const string SMTP_SERVER = "mail.jesse-brightman.com";
            try {
                MailMessage mailMsg  = new MailMessage(FROM, TO);
                mailMsg.Subject      = message.Subject;
                mailMsg.Body         = message.Body + "<br/>sent by: " + message.Sender;
                mailMsg.IsBodyHtml   = USE_HTML;

                SmtpClient smtp      = new SmtpClient();
                smtp.Port            = 25;
                smtp.Host            = SMTP_SERVER;
                smtp.Credentials     = new System.Net.NetworkCredential(FROM, FROM_PWD);
                smtp.Send(mailMsg);
            }
            catch (System.Exception ex) {
                return ex.Message;
            }
            return SUCCESS;
        }

        public bool SendEmail(string callbackUrl, RegisteredUser newUser)
        {
            string email = "Please confirm your account by clicking this link: <a href=\""
                                            + callbackUrl + "\">Confirm Registration</a>";
            string subject = "Please confirm your registration.";
            string response = EmailFromArvixe(
                                       new Email(newUser.Email, subject, email));
            return true;
        }
    }
}
