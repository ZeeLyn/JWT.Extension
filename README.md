# JWT.Extension

## Package & Status
Packages | NuGet
---------|------
JWT.Extension|[![NuGet package](https://buildstats.info/nuget/JWT.Extension)](https://www.nuget.org/packages/JWT.Extension)

## Configuration
```csharp
{
  "JwtAuthorize": {
    "Secret": "3A1D50FD-5450-4BA6-B6E8-D57143A0EFBB",
    "Issuer": "Issuer",
    "Audience": "Audience",
    "PolicyName": "",
    "RequireHttps": false
  }
}
```

## Register
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
    services.AddJwtBearerAuthorize();
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseAuthentication();
    app.UseMvc();
}
```

Custom authorization filter
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
    services.AddJwtBearerAuthorize<CustomAuthorizationFilter>();
}
```

## Generate token
```csharp
public class ValuesController : ControllerBase
{
	private IJwtTokenBuilder JwtTokenBuilder { get; }

	public LoginController(IJwtTokenBuilder tokenBuilder)
	{
		JwtTokenBuilder = tokenBuilder;
	}

	public IActionResult Login()
	{
		return Ok(JwtTokenBuilder.Build(new List<Claim> { new Claim("id", "1"), new Claim("powers", "get") }, TimeSpan.FromMinutes(1)));
	}
}
```
## Custom attribute
```csharp
[HttpPost]
[Permission(Powers = "post")]
public void Post([FromBody] string value)
{

}
```

