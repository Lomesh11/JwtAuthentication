using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using JWTAuthentication.Model;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Security.Claims;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        public IActionResult Login([FromBody]User login)
        {
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        private string GenerateJSONWebToken(User userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            //var claims = new[] {
            //    new Claim(JwtRegisteredClaimNames.Sub,userInfo.UserName),
            //    new Claim(JwtRegisteredClaimNames.Email,userInfo.UserEmail),
            //    //new Claim(JwtRegisteredClaimNames,userInfo.SessionId),
            //    new Claim("UserId",userInfo.UserId),
            //   // new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            //};
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(2),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private User AuthenticateUser(User login)
        {
            User user = null;

            //Validate the User Credentials  
            //Demo Purpose, I have Passed HardCoded User Information  
            if (login.UserName == "Jignesh")
            {
                user = new User { UserName = "Jignesh Trivedi", UserEmail = "test.btest@gmail.com" };
            }
            return user;
        }
    }
}