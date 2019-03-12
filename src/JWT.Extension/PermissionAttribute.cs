using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace JWT.Extension
{
    public class PermissionAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
        public string Powers { get; set; }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.Identity.IsAuthenticated)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var filter = context.HttpContext.RequestServices.GetService<IJwtAuthorizationFilter>();
            if (!filter.OnAuthorization(context, Roles, Powers, AuthenticationSchemes))
                context.Result = new ForbidResult();
        }
    }
}
