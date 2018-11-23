using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController: ControllerBase
    {
        private readonly IAuthRepository _repo;

        public IConfiguration _config { get; }

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        // public async Task<IActionResult> Register( string username, string password ) 
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto) 
        {
            //validate request

            // username = username.ToLower();
            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();

            // if( await _repo.UserExists(username) )
            if( await _repo.UserExists(userForRegisterDto.Username) )
                return BadRequest("Username already exists");

            var userToCreate = new User 
            {
                // Username = username
                Username = userForRegisterDto.Username
            };

            // var createdUser = _repo.Register(userToCreate, password);
            var createdUser = _repo.Register(userToCreate, userForRegisterDto.Password );

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login( UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repo.Login( userForLoginDto.Username.ToLower(), userForLoginDto.Password);

            if( userFromRepo == null )
                return Unauthorized();

            var claims = new[] 
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };

            var key = new SymmetricSecurityKey( Encoding.UTF8
                .GetBytes(_config.GetSection("AppSettings:Token").Value ) );

            var creds = new SigningCredentials( key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok( new {
                token = tokenHandler.WriteToken(token)
            });
        }

    }
}