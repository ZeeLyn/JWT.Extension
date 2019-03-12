using Microsoft.AspNetCore.Mvc.Filters;

namespace JWT.Extension
{
    public interface IJwtAuthorizationFilter
    {
        bool OnAuthorization(AuthorizationFilterContext context, string roles, string powers, string authenticationSchemes);
    }
}
