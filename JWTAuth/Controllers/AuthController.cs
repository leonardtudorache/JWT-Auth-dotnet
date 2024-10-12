using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using JWTAuth.Infrastructure;
using JWTAuth.Models;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly IUserService _userService;
        private readonly IJwtAuthManager _jwtAuthManager;
        private readonly DbContext _context;

        public AccountController(ILogger<AccountController> logger, IUserService userService, IJwtAuthManager jwtAuthManager, DbContext context)
        {
            _logger = logger;
            _userService = userService;
            _jwtAuthManager = jwtAuthManager;
            _context = context;
        }

        [AllowAnonymous]
        [HttpPost("Signup")]
        public async Task<ActionResult> Signup([FromBody] SignupRequest request)
        {
            string appSecret = "";
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            if (_userService.IsAnExistingUser(request.Email))
            {
                var response = new HttpResponseMessage()
                {
                    Content = new StringContent($"User already exists."),
                };
                return Conflict(response);

            }
            var userToRegister = new User
            {
                Email = request.Email,
                Password = Crypto.HashSHA1(request.Password),
                FirstName = request.Firstname,
                LastName = request.Lastname,
                Role = Role.User
            };

            var claims = new[]
            {
                new Claim(ClaimTypes.Name,request.Email),
                new Claim(ClaimTypes.Role, UserRoles.BasicUser)
            };


            if (userToRegister.Secrets == null)
            {
                userToRegister.Secrets = new List<AppSecret>();
            }
            var guidSecret = Guid.NewGuid();
            appSecret = guidSecret.ToString();
            userToRegister.Secrets.Add(new AppSecret
            {
                DeviceId = request.DeviceId,
                Secret = guidSecret
            });

            _context.Users.Add(userToRegister);

            await _context.SaveChangesAsync();

            var jwtResult = await _jwtAuthManager.GenerateTokens(request.Email, claims, DateTime.Now);
            _logger.LogInformation($"User [{request.Email}] logged in the system.");
            return Ok(new LoginResult
            {
                Email = request.Email,
                Role = UserRoles.BasicUser,
                AccessToken = jwtResult.AccessToken,
                RefreshToken = jwtResult.RefreshToken.TokenString,
                AppSecret = appSecret
            });
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<ActionResult> Login([FromBody] LoginRequest request)
        {
            string appSecret = "";
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            if (!_userService.IsValidUserCredentials(request.Email, request.Password))
            {
                return Unauthorized();
            }

            var role = _userService.GetUserRole(request.Email);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name,request.Email),
                new Claim(ClaimTypes.Role, role)
            };

            if (request.DeviceId == null ? false : request.DeviceId.Length > 0)
            {
                if (!_context.AuthSecret.Any(e => e.DeviceId == request.DeviceId))
                {
                    var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);
                    if (user.Secrets == null)
                    {
                        user.Secrets = new List<AppSecret>();
                    }
                    var guidSecret = Guid.NewGuid();
                    appSecret = guidSecret.ToString();
                    user.Secrets.Add(new AppSecret
                    {
                        DeviceId = request.DeviceId,
                        Secret = guidSecret
                    });
                    await _context.SaveChangesAsync();
                }
            }

            var jwtResult = await _jwtAuthManager.GenerateTokens(request.Email, claims, DateTime.Now);
            _logger.LogInformation($"User [{request.Email}] logged in the system.");
            return Ok(new LoginResult
            {
                Email = request.Email,
                Role = role,
                AccessToken = jwtResult.AccessToken,
                RefreshToken = jwtResult.RefreshToken.TokenString,
                AppSecret = appSecret
            });
        }

        [Authorize]
        [HttpPost("ResetPassword")]
        public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            if (!_userService.IsValidUserCredentials(User.Identity.Name, request.CurrentPassword))
            {
                return Unauthorized();
            }

            if (!await _userService.ResetPassword(User.Identity.Name, request.NewPassword))
            {
                return BadRequest();
            }

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, User.Identity.Name),
            };


            var jwtResult = await _jwtAuthManager.GenerateTokens(User.Identity.Name, claims, DateTime.Now);
            _logger.LogInformation($"User [{User.Identity.Name}] reset the password.");
            return Ok(new ResetPasswordResult
            {
                AccessToken = jwtResult.AccessToken,
                RefreshToken = jwtResult.RefreshToken.TokenString
            });
        }

        [HttpGet("User")]
        [Authorize]
        public ActionResult GetCurrentUser()
        {
            return Ok(new LoginResult
            {
                Email = User.Identity.Name,
                Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<ActionResult> Logout()
        {
            var userName = User.Identity.Name;
            await _jwtAuthManager.RemoveRefreshTokenByUserNameAsync(userName);
            _logger.LogInformation($"User [{userName}] logged out the system.");
            return Ok();
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<ActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                Guid appSecret;
                StringValues appSecretStringValues;
                var email = request.Email;
                _logger.LogInformation($"User [{email}] is trying to refresh JWT token.");

                if (string.IsNullOrWhiteSpace(request.RefreshToken))
                {
                    return Unauthorized();
                }

                HttpContext.Request.Headers.TryGetValue("Authorization", out appSecretStringValues);

                appSecret = new Guid(appSecretStringValues[0].Remove(0, 5));

                if (!_context.Users.First(u => u.Email == email).Secrets.Any(s => s.Secret == appSecret))
                {
                    return Unauthorized();
                }


                var role = _userService.GetUserRole(email);
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, email),
                    new Claim(ClaimTypes.Role, role)
                };

                var jwtResult = await _jwtAuthManager.Refresh(request.RefreshToken, email, claims, DateTime.Now);
                _logger.LogInformation($"User [{email}] has refreshed JWT token.");
                return Ok(new LoginResult
                {
                    Email = email,
                    Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty,
                    AccessToken = jwtResult.AccessToken,
                    RefreshToken = jwtResult.RefreshToken.TokenString
                });
            }
            catch (SecurityTokenException e)
            {
                return Unauthorized(e.Message); // return 401 so that the client side can redirect the user to login page
            }
        }
    }

    public class LoginRequest
    {
        [Required]
        [JsonPropertyName("Email")]
        public string Email { get; set; }

        [Required]
        [JsonPropertyName("Password")]
        public string Password { get; set; }
        [JsonPropertyName("DeviceId")]
        public string DeviceId { get; set; }
    }

    public class SignupRequest
    {
        [Required]
        [JsonPropertyName("Email")]
        public string Email { get; set; }

        [Required]
        [JsonPropertyName("Password")]
        public string Password { get; set; }
        [Required]
        [JsonPropertyName("Firstname")]
        public string Firstname { get; set; }
        [Required]
        [JsonPropertyName("Lastname")]
        public string Lastname { get; set; }
        [Required]
        [JsonPropertyName("DeviceId")]
        public string DeviceId { get; set; }
    }

    public class LoginResult
    {
        [JsonPropertyName("Email")]
        public string Email { get; set; }

        [JsonPropertyName("role")]
        public string Role { get; set; }

        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refreshToken")]
        public string RefreshToken { get; set; }
        [JsonPropertyName("AppSecret")]
        public string AppSecret { get; set; }
    }
    public class ResetPasswordRequest
    {
        [JsonPropertyName("CurrentPassword")]
        public string CurrentPassword { get; set; }
        [JsonPropertyName("NewPassword")]
        public string NewPassword { get; set; }


    }

    public class ResetPasswordResult
    {
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }
        [JsonPropertyName("refreshToken")]
        public string RefreshToken { get; set; }
    }

    public class RefreshTokenRequest
    {
        [JsonPropertyName("RefreshToken")]
        public string RefreshToken { get; set; }
        [JsonPropertyName("DeviceId")]
        public string DeviceId { get; set; }
        [JsonPropertyName("AppSecret")]
        public string AppSecret { get; set; }
        [Required]
        [JsonPropertyName("Email")]
        public string Email { get; set; }
    }
}
