using System;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Extension
{
    public static class ServiceCollectionExtension
    {
        public static AuthenticationBuilder AddJwtBearerAuthorize(this IServiceCollection serviceCollection)
        {
            return serviceCollection.AddJwtBearerAuthorize<JwtAuthorizationFilterDefault>();
        }

        public static AuthenticationBuilder AddJwtBearerAuthorize<TJwtAuthorizationFilter>(this IServiceCollection serviceCollection)
            where TJwtAuthorizationFilter : class, IJwtAuthorizationFilter
        {
            var configuration =
                serviceCollection.SingleOrDefault(s => s.ServiceType.Name == typeof(IConfiguration).Name)
                    ?.ImplementationInstance as IConfiguration;
            if (configuration == null)
                throw new ArgumentNullException(nameof(IConfiguration));

            var config = configuration.GetSection("JwtAuthorize");
            if (!config.Exists())
                throw new ArgumentNullException("JwtAuthorize", "JwtAuthorize configuration section not found.");

            var secret = config.GetValue<string>("secret");
            if (string.IsNullOrWhiteSpace(secret))
                throw new ArgumentNullException("secret");
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateIssuer = true,
                ValidIssuer = config.GetValue<string>("Issuer"),
                ValidateAudience = true,
                ValidAudience = config.GetValue<string>("Audience"),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                RequireExpirationTime = true
            };

            serviceCollection.AddSingleton<IJwtTokenBuilder, JwtTokenBuilder>();
            var authOptions = new AuthorizeOptions
            {
                Issuer = config.GetValue<string>("Issuer"),
                Audience = config.GetValue<string>("Audience"),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512Signature),
                AuthenticationScheme = JwtBearerDefaults.AuthenticationScheme
            };
            serviceCollection.AddSingleton(authOptions);
            serviceCollection.AddSingleton<IJwtAuthorizationFilter, TJwtAuthorizationFilter>();
            var policyName = config.GetValue<string>("PolicyName");
            if (!string.IsNullOrWhiteSpace(policyName))
                serviceCollection.AddAuthorization(options =>
                {
                    options.AddPolicy(policyName, builder => { builder.AddRequirements(authOptions); });
                });

            return serviceCollection
                .AddAuthentication(options => { options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme; })
                .AddJwtBearer(builder =>
                   {
                       builder.TokenValidationParameters = parameters;
                       builder.RequireHttpsMetadata = config.GetValue<bool>("RequireHttps");
                   });
        }
    }
}
