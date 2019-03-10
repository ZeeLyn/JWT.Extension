using System;
using Microsoft.Extensions.DependencyInjection;

namespace JWT.Extension
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection AddJWT(this IServiceCollection serviceCollection)
        {
            return serviceCollection;
        }
    }
}
