using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace JWT.Extension
{
    public interface IJwtTokenBuilder
    {
        JwtToken Build(IEnumerable<Claim> claims, TimeSpan expires);
    }

    public class JwtToken
    {
        public string Token { get; set; }

        public DateTime Expires { get; set; }

        public string Type { get; set; } = "Bearer";
    }
}
