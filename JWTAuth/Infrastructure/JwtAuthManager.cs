using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using JWTAuth.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuth.Infrastructure
{
    public interface IJwtAuthManager
    {
        Task<JwtAuthResult> GenerateTokens(string username, Claim[] claims, DateTime now);
        Task<JwtAuthResult> Refresh(string refreshToken, string userName, Claim[] claims, DateTime now);
        void RemoveExpiredRefreshTokens(DateTime now);
        Task RemoveRefreshTokenByUserNameAsync(string userName);
        (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);
    }

    public class JwtAuthManager : IJwtAuthManager
    {
        private readonly DbSet<JWTAuth.Models.RefreshToken> _usersRefreshTokens;  // can store in a database or a distributed cache
        private readonly JwtTokenConfig _jwtTokenConfig;
        private readonly byte[] _secret;
        private DbContext _context;

        public JwtAuthManager(JwtTokenConfig jwtTokenConfig)
        {
            _context = new DbContext();
            _jwtTokenConfig = jwtTokenConfig;
            _usersRefreshTokens = _context.RefreshTokens;
            _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret);
        }

        // optional: clean up expired refresh tokens - to be implemented
        public void RemoveExpiredRefreshTokens(DateTime now)
        {
            var expiredTokens = _usersRefreshTokens.Where(x => x.ExpireAt < now).ToList();
            foreach (var expiredToken in expiredTokens)
            {
                //_usersRefreshTokens.TryRemove(expiredToken.Key, out _);
            }
        }

        // can be more specific to ip, user agent, device name, etc. - to be implemented
        public async Task RemoveRefreshTokenByUserNameAsync(string userName)
        {
            var token = _context.RefreshTokens.First(u => u.UserName == userName);
            var refreshTokens = _usersRefreshTokens.Remove(token);

            await _context.SaveChangesAsync();
        }

        public async Task<JwtAuthResult> GenerateTokens(string username, Claim[] claims, DateTime now)
        {
            var shouldAddAudienceClaim = string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
            var jwtToken = new JwtSecurityToken(
                _jwtTokenConfig.Issuer,
                shouldAddAudienceClaim ? _jwtTokenConfig.Audience : string.Empty,
                claims,
                expires: now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(_secret), SecurityAlgorithms.HmacSha256Signature));
            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            var refreshToken = new RefreshToken
            {
                UserName = username,
                TokenString = GenerateRefreshTokenString(),
                ExpireAt = now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration)
            };

            var dbRefreshToken = _usersRefreshTokens.FirstOrDefault(r => r.UserName == username);
            if (dbRefreshToken != null)
            {
                dbRefreshToken.TokenString = Crypto.HashSHA1(refreshToken.TokenString);
            }
            else
            {
                _usersRefreshTokens.Add(new JWTAuth.Models.RefreshToken()
                {
                    ExpireAt = refreshToken.ExpireAt,
                    TokenString = Crypto.HashSHA1(refreshToken.TokenString),
                    UserName = refreshToken.UserName
                });
            }

            await _context.SaveChangesAsync();

            return new JwtAuthResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public async Task<JwtAuthResult> Refresh(string refreshToken, string userName, Claim[] claims, DateTime now)
        {
            string hashedRefreshToken = Crypto.HashSHA1(refreshToken);

            var existingRefreshToken = _usersRefreshTokens.FirstOrDefault(r => r.UserName == userName && r.TokenString == hashedRefreshToken);
            if (existingRefreshToken == null)
            {
                throw new SecurityTokenException("Invalid token");
            }
            if (existingRefreshToken.UserName != userName || existingRefreshToken.ExpireAt < now)
            {
                throw new SecurityTokenException("Invalid token");
            }

            return await GenerateTokens(userName, claims, now); // need to recover the original claims
        }

        public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new SecurityTokenException("Invalid token");
            }
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token,
                    new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = _jwtTokenConfig.Issuer,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(_secret),
                        ValidAudience = _jwtTokenConfig.Audience,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(1)
                    },
                    out var validatedToken);
            return (principal, validatedToken as JwtSecurityToken);
        }

        private static string GenerateRefreshTokenString()
        {
            var randomNumber = new byte[32];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public class JwtAuthResult
    {
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refreshToken")]
        public RefreshToken RefreshToken { get; set; }
    }

    public class RefreshToken
    {
        [JsonPropertyName("username")]
        public string UserName { get; set; }    // can be used for usage tracking
        // can optionally include other metadata, such as user agent, ip address, device name, and so on

        [JsonPropertyName("tokenString")]
        public string TokenString { get; set; }

        [JsonPropertyName("expireAt")]
        public DateTime ExpireAt { get; set; }
    }
}
