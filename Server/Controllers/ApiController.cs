using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Server;

namespace AuthAndRefreshTokenDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ApiController : ControllerBase
    {
        private static Application _application = new Application();

        // We need some extra security here to ensure that call is only comming from our client
        [HttpGet]
        public IActionResult GetRefreshToken([FromQuery] Guid clientId)
        {
            var refreshTokenValue = TokenUtil.GenerateRefreshToken(clientId);

            _application.SetRefreshToken(new RefreshToken(clientId, refreshTokenValue));

            return Ok(refreshTokenValue);
        }

        // We may need some extra security here to ensure that call is only comming from our client
        [HttpGet]
        [Authorize] // The refresh token gives access for the clients
        public IActionResult GetAccessToken(string refreshToken)
        {
            var existingRefreshToken = GetRefreshTokenFromClaim();
            if (existingRefreshToken == null)
            {
                return Unauthorized();
            }

            if (refreshToken != existingRefreshToken.TokenValue)
            {
                // Someone else has used the refresh token, so it might be compromised, kick off the client and require a new token flow
                _application.RemoveRefreshToken(existingRefreshToken.ClientId);
                return Unauthorized();
            }

            var acceccTokenValue = TokenUtil.GenerateAccessToken(existingRefreshToken.ClientId, existingRefreshToken.UserId);
            var refreshTokenValue = TokenUtil.GenerateRefreshToken(existingRefreshToken.ClientId);

            _application.SetRefreshToken(new RefreshToken(existingRefreshToken.ClientId, refreshTokenValue, existingRefreshToken.UserId));

            return Ok(new { AccessToken = acceccTokenValue, RefreshToken = refreshTokenValue });
        }

        [HttpGet]
        [Authorize] // No third party can access, but endpoint is open for all clients even if they has not yet logged in
        public IActionResult SomeOpenEndpoint()
        {
            return Ok($"You got access to the open endpoint, clientId: {GetClientIdFromClaim()}, userId: {GetUserIdFromClaim()}");
        }

        [HttpPost]
        [Authorize] // Only our clients has access
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var userId = _application.AuthenticateUser(request.Username, request.Password);
            if (userId == null)
            {
                // username or password was wrong
                return Unauthorized();
            }

            var existingRefreshToken = GetRefreshTokenFromClaim();
            if (existingRefreshToken == null)
            {
                return Unauthorized();
            }

            _application.SetRefreshToken(new RefreshToken(existingRefreshToken.ClientId, existingRefreshToken.TokenValue, userId));

            return Ok();
        }

        [HttpGet]
        [Authorize(Roles = "LoggedIn")] // Only access for logged in clients
        public IActionResult SomeRestrictedEndpoint()
        {
            return Ok($"You got access to the restricted endpoint, clientId: {GetClientIdFromClaim()}, userId: {GetUserIdFromClaim()}");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")] // Only admins has access
        public IActionResult ForceLogout(Guid userId)
        {
            _application.ForceLogout(userId);
            return Ok();
        }

        private RefreshToken? GetRefreshTokenFromClaim()
        {
            var clientId = GetClientIdFromClaim();
            if (clientId == null)
            {
                return null;
            }

            var refreshToken = _application.GetRefreshToken(clientId.Value);
            if (refreshToken == null)
            {
                // Refresh token may have been removed due to malicious usage
                return null;
            }

            return refreshToken;
        }

        private Guid? GetClientIdFromClaim()
        {
            if (!HttpContext.User.HasClaim(c => c.Type == "client_id"))
            {
                // Invalid token
                return null;
            }

            return Guid.Parse(HttpContext.User.Claims.First(c => c.Type == "client_id").Value);
        }

        private Guid? GetUserIdFromClaim()
        {
            if (!HttpContext.User.HasClaim(c => c.Type == "user_id"))
            {
                return null;
            }

            return Guid.Parse(HttpContext.User.Claims.First(c => c.Type == "user_id").Value);
        }

        public record LoginRequest(string Username, string Password);
    }
}