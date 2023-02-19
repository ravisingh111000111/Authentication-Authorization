using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CityInfo.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthenticationController(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }
        public class AuthenticationRequestBody
        {
            public string? UserName { get; set; }
            public string? Password { get; set; }
        }

        private class CityInfoUser
        {
            public int UserId { get; set; }
            public string UserName { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string City { get; set; }

            public CityInfoUser(int userId,
                                string userName,
                                string firstName,
                                string lastName,
                                string city)
            {
                UserId = userId;
                UserName = userName;
                FirstName = firstName;
                LastName = lastName;
                City = city;
            }
        }
        [HttpPost("authenticate")]
        public ActionResult<string> Authenticate(AuthenticationRequestBody authenticationRequestBody)
        {
            // Step 1: Validate username and password

            var user = ValidateUserCredentials(authenticationRequestBody);

            if (user == null)
                return Unauthorized();

            // Step 2: Create a token
            var securityKey = new SymmetricSecurityKey(
                Encoding.ASCII.GetBytes(_configuration["Authentication:SecretForKey"]));
            var signingCredentials = new SigningCredentials(securityKey,
                                                        SecurityAlgorithms.HmacSha256);
            var claimsForToken = new List<Claim>();
            claimsForToken.Add(new Claim("sub", user.UserId.ToString()));
            claimsForToken.Add(new Claim("given_name", user.FirstName));
            claimsForToken.Add(new Claim("family_name", user.LastName));
            claimsForToken.Add(new Claim("city", user.City));

            var token = new JwtSecurityToken(
                _configuration["Authentication:Issuer"],
                _configuration["Authentication:Audience"],
                claimsForToken,
                DateTime.Now,
                DateTime.Now.AddHours(1),
                signingCredentials);

            var tokenToReturn = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(tokenToReturn);

        }

        private CityInfoUser ValidateUserCredentials(AuthenticationRequestBody authenticationRequestBody)
        {
            // For demo we assume that credentials are valid
            // In real scenario we would have got the user details from DB
            return new CityInfoUser(
                1,
                authenticationRequestBody.UserName ?? "",
                "Ravi",
                "Singh",
                "Bokaro"
                );
        }
    }
}
