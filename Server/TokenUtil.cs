using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Server
{
    public static class TokenUtil
    {
        // Get values from config
        public static string RefreshTokenSecret = "super_secret_refresh_key_and_it_has_to_bee_long";
        public static string AccessTokenSecret = "super_secret_auth_key_and_it_has_to_bee_long";
        public static string Issuer = "AuthAndRefreshTokenDemo";

        public static string GenerateRefreshToken(Guid clientId, Guid refreshId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim("client_id", clientId.ToString()),
                new Claim("refresh_id", refreshId.ToString()),
                new Claim(ClaimTypes.Role, "Refresh")
            };

            var token = new JwtSecurityToken(Issuer,
                Issuer,
                claims,
                expires: DateTime.Now.AddMonths(3), // Give long life time to avoid clients has to re-login
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static string GenerateAccessToken(Guid clientId, Guid? userId, params string[] roles)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AccessTokenSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>();
            claims.Add(new Claim("client_id", clientId.ToString()));
            if (userId != null)
            {
                claims.Add(new Claim("user_id", userId.Value.ToString() ?? ""));
            }
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(Issuer,
                Issuer,
                claims,
                expires: DateTime.Now.AddMinutes(10), // Give short life time as a new token can be given with refresh token
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static Guid? GetClientId(this HttpContext httpContext)
        {
            var claim = httpContext.User.Claims.FirstOrDefault(c => c.Type == "client_id");
            if (claim == null)
            {
                return null;
            }
            return Guid.Parse(claim.Value);
        }

        public static Guid? GetRefreshId(this HttpContext httpContext)
        {
            var claim = httpContext.User.Claims.FirstOrDefault(c => c.Type == "refresh_id");
            if (claim == null)
            {
                return null;
            }
            return Guid.Parse(claim.Value);
        }

        public static Guid? GetUserId(this HttpContext httpContext)
        {
            var claim = httpContext.User.Claims.FirstOrDefault(c => c.Type == "user_id");
            if (claim == null)
            {
                return null;
            }
            return Guid.Parse(claim.Value);
        }
    }
}
