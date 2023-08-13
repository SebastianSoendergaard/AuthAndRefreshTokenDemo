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
        public static string Audience = "AuthAndRefreshTokenDemo";

        public static string GenerateRefreshToken(Guid clientId, Guid refreshId)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim("client_id", clientId.ToString()),
                new Claim("refresh_id", refreshId.ToString())
            };

            var token = new JwtSecurityToken(Issuer,
                Audience,
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
                Audience,
                claims,
                expires: DateTime.Now.AddMinutes(10), // Give short life time as a new token can be given with refresh token
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static bool TryValidateRefreshToken(string refreshToken, out Guid clientId, out Guid refreshId)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();

                handler.ValidateToken(refreshToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Issuer,
                    ValidAudience = Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSecret))
                },
                out var validatedToken);

                var jwtSecurityToken = handler.ReadJwtToken(refreshToken);

                var cid = jwtSecurityToken.Claims.First(claim => claim.Type == "client_id").Value;
                var rid = jwtSecurityToken.Claims.First(claim => claim.Type == "refresh_id").Value;

                clientId = Guid.Parse(cid);
                refreshId = Guid.Parse(rid);

                return true;
            }
            catch
            {
                clientId = Guid.Empty;
                refreshId = Guid.Empty;
                return false;
            }
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
