using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using DreamTravelWebAPI.Models;
using DreamTravelWebAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace DreamTravelWebAPI.Controllers
{
    
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IConfiguration _config;
        private readonly JwtSettings _jwtSettings;
        public UsersController(IUserService userService, IConfiguration config, IOptions<JwtSettings> jwtSettings)
        {
            _userService = userService;
            _config = config;
            _jwtSettings = jwtSettings.Value;
        }

        // Register a new user
        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register([FromBody] User user)
        {

            if (_userService.Exists(user.NIC))
                return BadRequest("User already exists");

            user.IsActive = true; // Set new users to active by default

            _userService.HashPassword(user);
             user.Id = null;
            _userService.Create(user);
            return Ok("User successfully registered");
        }



        // Authenticate the user and return a JWT
        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDTO loginData)
        {
            var user = _userService.GetByNic(loginData.NIC);
            if (user == null || !_userService.ValidatePassword(user, loginData.Password))
                return BadRequest("Username or password is incorrect");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Name, user.NIC),
                new Claim(System.Security.Claims.ClaimTypes.Role, user.Role.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString });
        }

        // Get user details
        [HttpGet("{nic}")]
        public IActionResult GetUserDetails(string nic)
        {
            var user = _userService.GetByNic(nic);
            if (user == null)
                return NotFound();
            user.Password = null; // Clear the password before returning
            return Ok(user);
        }

        // Update user details
        [HttpPut("{nic}")]
        public IActionResult UpdateUser(string nic, [FromBody] User userParam)
        {
            var user = _userService.GetByNic(nic);
            if (user == null)
                return NotFound();

            _userService.HashPassword(userParam);
            _userService.Update(nic, userParam);
            return Ok("User updated successfully");
        }

        // Delete a user
        [HttpDelete("{nic}")]
        public IActionResult DeleteUser(string nic)
        {
            if (_userService.GetByNic(nic) == null)
                return NotFound();

            _userService.Delete(nic);
            return Ok("User deleted successfully");
        }

        // Activate a user
        [HttpPatch("{nic}/activate")]
        public IActionResult ActivateUser(string nic)
        {
            var user = _userService.GetByNic(nic);
            if (user == null)
                return NotFound();

            user.IsActive = true;
            _userService.Update(nic, user);
            return Ok("User activated successfully");
        }

        // Deactivate a user
        [HttpPatch("{nic}/deactivate")]
        public IActionResult DeactivateUser(string nic)
        {
            var user = _userService.GetByNic(nic);
            if (user == null)
                return NotFound();

            user.IsActive = false;
            _userService.Update(nic, user);
            return Ok("User deactivated successfully");
        }
    }
}
