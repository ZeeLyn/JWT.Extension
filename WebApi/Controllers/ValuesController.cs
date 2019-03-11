using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JWT.Extension;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
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
            return Ok(JwtTokenBuilder.Build(new List<Claim> { new Claim("id", "1") }, TimeSpan.FromMinutes(5)));
        }

        // GET api/values/5
        [HttpGet("{id}")]
        [Permission()]
        public ActionResult<string> Get(int id)
        {

            return "value";
        }

        // POST api/values
        [HttpPost]
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
