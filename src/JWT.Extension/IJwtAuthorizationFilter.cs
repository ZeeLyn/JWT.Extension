using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;

namespace JWT.Extension
{
    public interface IJwtAuthorizationFilter
    {
        bool OnAuthorization(AuthorizationFilterContext context, string roles, string powers, string authenticationSchemes);
    }
}
