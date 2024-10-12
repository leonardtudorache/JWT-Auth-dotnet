using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWTAuth.Models;
using Microsoft.Extensions.Logging;

namespace JWTAuth.Services
{
    public interface IUserService
    {
        bool IsAnExistingUser(string userName);
        bool IsValidUserCredentials(string userName, string password);
        string GetUserRole(string userName);
        Task<bool> ResetPassword(string email, string password);
    }

    public class UserService : IUserService
    {
        private readonly ILogger<UserService> _logger;

        // inject your database here for user validation
        public UserService(ILogger<UserService> logger)
        {
            _logger = logger;
        }

        public bool IsValidUserCredentials(string email, string password)
        {
            var _context = new DbContext();
            _logger.LogInformation($"Validating user [{email}]");

            if(IsAnExistingUser(email))
            if (string.IsNullOrWhiteSpace(email))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }
            string hashedPassword = Crypto.HashSHA1(password);

            return _context.Users.Any(u => u.Email == email && u.Password == hashedPassword);
        }

        public bool IsAnExistingUser(string email)
        {
            var _context = new DbContext();
            return _context.Users.Any(u => u.Email == email);
        }
        public async Task<bool> ResetPassword(string email, string password)
        {
            var _context = new DbContext();
            var user = _context.Users.First(u => u.Email == email);
            user.Password = Crypto.HashSHA1(password);
            await _context.SaveChangesAsync();
            return true;
        }

        public string GetUserRole(string userName)
        {
            var _context = new DbContext();
            var user = _context.Users.First(u => u.Email == userName);
            if (user == null)
            {
                return string.Empty;
            }

            if (user.Role == Role.Admin)
            {
                return UserRoles.Admin;
            }

            return UserRoles.BasicUser;
        }
    }

    public static class UserRoles
    {
        public const string Admin = nameof(Admin);
        public const string BasicUser = nameof(BasicUser);
    }
}
