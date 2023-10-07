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

namespace DreamTravelWebAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IConfiguration _config;

        public UsersController(IUserService userService, IConfiguration config)
        {
            _userService = userService;
            _config = config;
        }

        // Register a new user
        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult Register([FromBody] User userParam)
        {
            if (_userService.Exists(userParam.NIC))
                return BadRequest("User already exists");

            _userService.HashPassword(userParam);
            _userService.Create(userParam);
            return Ok("User successfully registered");
        }

        // Authenticate the user and return a JWT
        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Login([FromBody] User userParam)
        {
            var user = _userService.GetByNic(userParam.NIC);
            if (user == null || !_userService.ValidatePassword(user, userParam.Password))
                return BadRequest("Username or password is incorrect");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["JwtSettings:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.NIC),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
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
