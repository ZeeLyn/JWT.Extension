using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Extension
{
    public class AuthorizeOptions : IAuthorizationRequirement
    {

        public string Issuer { get; internal set; }

        public string Audience { get; internal set; }

        public SigningCredentials SigningCredentials { get; internal set; }

        public string AuthenticationScheme { get; internal set; }
    }
}
