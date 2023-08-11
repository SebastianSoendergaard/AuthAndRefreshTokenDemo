using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Server
{
    public static class TokenUtil
    {
        // Get values from config
        private static string RefreshTokenSecret = "super_secret_key";
        private static string AccessTokenSecret = "super_secret_key";
        private static string Issuer = "AuthAndRefreshTokenDemo";

        public static string GenerateRefreshToken(Guid clientId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim("client_id", clientId.ToString())
            };

            var token = new JwtSecurityToken(Issuer,
                Issuer,
                claims,
                expires: DateTime.Now.AddMonths(3), // Give long life time to avoid clients has to re-login
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static string GenerateAccessToken(Guid clientId, Guid? userId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AccessTokenSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>();
            claims.Add(new Claim("client_id", clientId.ToString()));
            if (userId != null)
            {
                claims.Add(new Claim("user_id", userId?.ToString() ?? ""));
                claims.Add(new Claim(ClaimTypes.Role, "LoggedIn"));
            }

            var token = new JwtSecurityToken(Issuer,
                Issuer,
                claims,
                expires: DateTime.Now.AddMinutes(10), // Give short life time as a new token can be given with refresh token
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
