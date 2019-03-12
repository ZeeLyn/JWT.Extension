using System;
using System.Collections.Generic;
using System.Security.Claims;
using JWT.Extension;
using Microsoft.AspNetCore.Mvc;

namespace Sample.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private IJwtTokenBuilder JwtTokenBuilder { get; }

        public ValuesController(IJwtTokenBuilder tokenBuilder)
        {
            JwtTokenBuilder = tokenBuilder;
        }

        // GET api/values
        [HttpGet]
        public IActionResult Get()
        {
            return Ok(JwtTokenBuilder.Build(new List<Claim> { new Claim("id", "1"), new Claim("powers", "get") }, TimeSpan.FromMinutes(1)));
        }

        // GET api/values/5
        [HttpGet("{id}")]
        [Permission(Powers = "get")]
        public ActionResult<string> Get(int id)
        {

            return "value";
        }

        // POST api/values
        [HttpPost]
        [Permission(Powers = "post", Policy = "a")]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
