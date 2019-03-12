using System;
using System.Linq;
using Microsoft.AspNetCore.Mvc.Filters;

namespace JWT.Extension
{
    public class JwtAuthorizationFilterDefault : IJwtAuthorizationFilter
    {
        public bool OnAuthorization(AuthorizationFilterContext context, string roles, string powers, string authenticationSchemes)
        {

            if (string.IsNullOrWhiteSpace(powers))
                return true;
            var claimPowers = context.HttpContext.User.Claims.FirstOrDefault(p => p.Type.Equals("powers", StringComparison.CurrentCultureIgnoreCase))?.Value;

            if (string.IsNullOrWhiteSpace(claimPowers))
                return false;

            if (claimPowers.Equals("all", StringComparison.CurrentCultureIgnoreCase))
                return true;

            if (claimPowers.Equals("none", StringComparison.CurrentCultureIgnoreCase))
                return false;

            var requiredPowers = powers.Split(',');
            var userHasPowers = claimPowers.Split(',');
            if (!requiredPowers.Any(p => userHasPowers.Contains(p)))
                return false;
            return true;
        }
    }
}
