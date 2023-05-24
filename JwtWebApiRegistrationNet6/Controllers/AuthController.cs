using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApiRegistrationNet6.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration) // need for read appsetting.json
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request) {

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (user.Username != request.Username) {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)) 
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user) { //creating json web token
            List<Claim> claims = new List<Claim> // add using System.Security.Claims;
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(  // install package Microsoft.IdentityModel.Tokens
                _configuration.GetSection("AppSetting:Token").Value));
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            
            var token = new JwtSecurityToken( // install package system.identitymodel.tokens.jwt
                claims : claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);
           
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            
            return jwt;
        }


        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)  
        {
            using (var hmac = new HMACSHA512()) {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt) {

            using (var hmac = new HMACSHA512(passwordSalt)) {

                var computerHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computerHash.SequenceEqual(passwordHash);
            }

        }
    }
}
