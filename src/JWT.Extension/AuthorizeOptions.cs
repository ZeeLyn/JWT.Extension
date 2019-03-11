using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Extension
{
    public class AuthorizeOptions
    {

        public string Issuer { get; set; }

        public string Audience { get; set; }

        public SigningCredentials SigningCredentials { get; set; }

        public string AuthenticationScheme { get; set; }
    }
}
