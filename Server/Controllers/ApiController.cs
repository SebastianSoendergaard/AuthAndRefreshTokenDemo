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
        [HttpGet("GetRefreshToken")]
        public IActionResult GetRefreshToken([FromQuery] Guid clientId)
        {
            if (clientId == Guid.Empty)
            {
                return BadRequest("clientId missing");
            }

            var refreshId = Guid.NewGuid();

            string refreshTokenValue = "";
            try
            {
                refreshTokenValue = TokenUtil.GenerateRefreshToken(clientId, refreshId);
            }
            catch (Exception ex)
            {
                throw;
            }

            _application.SetRefreshToken(new RefreshToken(clientId, refreshId));

            return Ok(refreshTokenValue);
        }

        // We may need some extra security here to ensure that call is only comming from our client
        [HttpGet("GetAccessToken")]
        [Authorize(Roles = "Refresh")] // Client need a refresh token to access
        public IActionResult GetAccessToken()
        {
            var existingRefreshToken = GetExistingRefreshToken();
            if (existingRefreshToken == null)
            {
                return Unauthorized();
            }

            // Token Rotation
            // Create new refresh token every time we generate an access token 
            var newRefreshId = Guid.NewGuid();
            var newRefreshTokenValue = TokenUtil.GenerateRefreshToken(existingRefreshToken.ClientId, newRefreshId);
            _application.SetRefreshToken(new RefreshToken(existingRefreshToken.ClientId, newRefreshId, existingRefreshToken.UserId));

            var roles = GetRoles(existingRefreshToken.ClientId).ToArray();
            var acceccTokenValue = TokenUtil.GenerateAccessToken(existingRefreshToken.ClientId, existingRefreshToken.UserId, roles);

            return Ok(new { AccessToken = acceccTokenValue, RefreshToken = newRefreshTokenValue });
        }

        [HttpGet("SomeOpenEndpoint")]
        [Authorize] // No third party can access, but endpoint is open for all authorized clients even if they has not yet logged in
        public IActionResult SomeOpenEndpoint()
        {
            return Ok($"You got access to the open endpoint, clientId: {HttpContext.GetClientId()}, userId: {HttpContext.GetUserId()}");
        }

        [HttpPost("Login")]
        [Authorize] // Only our authorized clients has access
        public IActionResult Login([FromBody] LoginRequest request)
        {
            var user = _application.AuthenticateUser(request.Username, request.Password);
            if (user == null)
            {
                // username or password was wrong
                return Unauthorized();
            }

            var existingRefreshToken = GetExistingRefreshToken();
            if (existingRefreshToken == null)
            {
                return Unauthorized();
            }

            _application.SetRefreshToken(new RefreshToken(existingRefreshToken.ClientId, existingRefreshToken.RefreshId, user.UserId));

            return Ok();
        }

        [HttpGet("SomeRestrictedEndpoint")]
        [Authorize(Roles = "LoggedIn")] // Only access for logged in clients
        public IActionResult SomeRestrictedEndpoint()
        {
            return Ok($"You got access to the restricted endpoint, clientId: {HttpContext.GetClientId()}, userId: {HttpContext.GetUserId()}");
        }

        [HttpPost("ForceLogout")]
        [Authorize(Roles = "Admin")] // Only admins has access
        public IActionResult ForceLogout(Guid userId)
        {
            _application.ForceLogout(userId);
            return Ok();
        }

        private RefreshToken? GetExistingRefreshToken()
        {
            var clientId = HttpContext.GetClientId();
            if (clientId == null)
            {
                // Invalid token
                return null;
            }

            var refreshId = HttpContext.GetRefreshId();
            if (refreshId == null)
            {
                // Invalid token
                return null;
            }

            var existingRefreshToken = _application.GetRefreshToken(clientId.Value);
            if (existingRefreshToken == null)
            {
                // Refresh token may have been removed due to Reuse Detection
                return null;
            }

            if (refreshId != existingRefreshToken.RefreshId)
            {
                // Reuse Detection
                // Someone else has used the refresh token, so it might be compromised
                // Remove refresh token to kick off the client and require a new token flow
                _application.RemoveRefreshToken(existingRefreshToken.ClientId);
                return null;
            }

            return existingRefreshToken;
        }

        private IEnumerable<string> GetRoles(Guid? userId)
        {
            if (userId != null)
            {
                var user = _application.GetUser(userId.Value);
                if (user != null)
                {
                    yield return "LoggedIn";

                    if (user.IsAdmin)
                    {
                        yield return "Admin";
                    }
                }
            }
        }

        public record LoginRequest(string Username, string Password);
    }
}