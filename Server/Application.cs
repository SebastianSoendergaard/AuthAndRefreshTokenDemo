namespace Server
{
    public class Application
    {
        private Dictionary<Guid, RefreshToken> _refreshTokens = new();
        private List<User> _users = new List<User>
        {
            new User(Guid.NewGuid(), "Tarzan", "ooohiooh"),
            new User(Guid.NewGuid(), "Jane", "help"),
            new User(Guid.NewGuid(), "Cheeta", "uhuh", true)
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

        public User? AuthenticateUser(string username, string password)
        {
            // perform the very complex validation here
            var user = _users.FirstOrDefault(u => u.Username == username && u.Password == password);
            if (user == null)
            {
                return null;
            }

            return user;
        }

        public User? GetUser(Guid userId)
        {
            return _users.SingleOrDefault(u => u.UserId == userId);
        }

        public void ForceLogout(Guid userId)
        {
            var refreshTokensForUser = _refreshTokens.Where(kv => kv.Value.UserId == userId).Select(kv => kv.Value);

            foreach (var refreshToken in refreshTokensForUser)
            {
                SetRefreshToken(new RefreshToken(refreshToken.ClientId, refreshToken.RefreshId));
            }
        }
    }

    public record RefreshToken(Guid ClientId, Guid RefreshId, Guid? UserId = null);
    public record User(Guid UserId, string Username, string Password, bool IsAdmin = false);
}
