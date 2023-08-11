namespace Server
{
    public class Application
    {
        private Dictionary<Guid, RefreshToken> _refreshTokens = new();
        private List<User> _users = new List<User>
        {
            new User(Guid.NewGuid(), "Tarzan", "uoh"),
            new User(Guid.NewGuid(), "Jane", "help"),
        };

        public void SetRefreshToken(RefreshToken token)
        {
            _refreshTokens[token.ClientId] = token;
        }

        public void RemoveRefreshToken(Guid clientId)
        {
            _refreshTokens.Remove(clientId);
        }

        public RefreshToken? GetRefreshToken(Guid clientId)
        {
            return _refreshTokens.TryGetValue(clientId, out var refreshToken) ? refreshToken : null;
        }

        public Guid? AuthenticateUser(string username, string password)
        {
            // perform the very complex validation here
            var user = _users.FirstOrDefault(u => u.Username == username && u.Password == password);
            if (user == null)
            {
                return null;
            }

            return user.UserId;
        }

        public void ForceLogout(Guid userId)
        {
            var refreshTokensForUser = _refreshTokens.Where(kv => kv.Value.UserId == userId).Select(kv => kv.Value);

            foreach (var refreshToken in refreshTokensForUser)
            {
                SetRefreshToken(new RefreshToken(refreshToken.ClientId, refreshToken.TokenValue));
            }
        }
    }

    public record RefreshToken(Guid ClientId, string TokenValue, Guid? UserId = null);
    public record User(Guid UserId, string Username, string Password);
}
