using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Server
{
    public static class TokenUtil
    {
        // Get values from config
        public static string RefreshTokenSigningSecret = "super_secret_refresh_signing_key_and_it_has_to_bee_very_long" + Guid.NewGuid().ToString() + Guid.NewGuid().ToString();
        public static string RefreshTokenEncryptingSecret = "super_secret_refresh_encryption_key_and_it_has_to_bee_very_long" + Guid.NewGuid().ToString() + Guid.NewGuid().ToString();
        public static string AccessTokenSecret = "super_secret_auth_key_and_it_has_to_bee_long";
        public static string Issuer = "Issuer";
        public static string Audience = "Audience";

        public static string GenerateRefreshToken(Guid clientId, Guid refreshId)
        {
            // See for encrypted refresh token https://stackoverflow.com/questions/18223868/how-to-encrypt-jwt-security-token

            List<Claim> claims = new List<Claim>()
            {
                new Claim("client_id", clientId.ToString()),
                new Claim("refresh_id", refreshId.ToString())
            };

            var signingSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSigningSecret.Substring(0, 127)));
            var encryptingSecurityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(RefreshTokenEncryptingSecret.Substring(0, 127)));

            var signingCredentials = new SigningCredentials(signingSecurityKey, SecurityAlgorithms.Sha512);

            var encryptingCredentials = new EncryptingCredentials(
                encryptingSecurityKey,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JwtSecurityTokenHandler();

            var jwtSecurityToken = handler.CreateJwtSecurityToken(
                Issuer,
                Audience,
                new ClaimsIdentity(claims),
                DateTime.Now,
                DateTime.Now.AddMonths(3), // Give long life time to avoid clients has to re-login
                DateTime.Now,
                signingCredentials);


            string tokenString = handler.WriteToken(jwtSecurityToken);

            return tokenString;



            //var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(RefreshTokenSecret));
            //var credentials = new SigningCredentials(signingSecurityKey, SecurityAlgorithms.HmacSha256);

            //var claims = new[] {
            //    new Claim("client_id", clientId.ToString()),
            //    new Claim("refresh_id", refreshId.ToString()),
            //    new Claim(ClaimTypes.Role, "Refresh")
            //};

            //var jwtToken = new JwtSecurityToken(Issuer,
            //    Issuer,
            //    claims,
            //    expires: DateTime.Now.AddMonths(3), // Give long life time to avoid clients has to re-login
            //    signingCredentials: credentials);




            //var jwtTokenSting = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            //string encryptedToken = "";
            //using (var encryptionProvider = credentials.CryptoProviderFactory.CreateAuthenticatedEncryptionProvider(signingSecurityKey, SecurityAlgorithms.HmacSha256))
            //{
            //    var encryptionResult = encryptionProvider.Encrypt(Encoding.UTF8.GetBytes(jwtTokenSting), Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));

            //    encryptedToken = $"{Base64UrlEncoder.Encode(encryptionResult.IV)}.{Base64UrlEncoder.Encode(encryptionResult.Ciphertext)}.{Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag)}";
            //}

            ////try
            ////{
            ////    var t = new JwtSecurityTokenHandler().ReadToken(str);
            ////    var t2 = new JwtSecurityTokenHandler().ReadJwtToken(str);
            ////    var t3 = new JwtSecurityTokenHandler().ValidateToken(str, new TokenValidationParameters() { }, out var validatedToken);
            ////}
            ////catch (Exception ex)
            ////{

            ////}

            //return "";
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
