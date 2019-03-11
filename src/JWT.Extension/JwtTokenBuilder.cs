using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JWT.Extension
{
    public class JwtTokenBuilder : IJwtTokenBuilder
    {
        private AuthorizeOptions Options { get; }

        public JwtTokenBuilder(AuthorizeOptions options)
        {
            Options = options;
        }

        public JwtToken Build(IEnumerable<Claim> claims, TimeSpan expires)
        {
            var notBefore = DateTime.UtcNow;
            var jwtHeader = new JwtHeader(Options.SigningCredentials);
            var expired = DateTime.Now.Add(expires);
            var jwtPayload = new JwtPayload(Options.Issuer, Options.Audience, claims, notBefore, expired);
            var jwt = new JwtSecurityToken(jwtHeader, jwtPayload);
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return new JwtToken
            {
                Token = token,
                Expires = expired,
                Type = Options.AuthenticationScheme
            };
        }
    }
}
