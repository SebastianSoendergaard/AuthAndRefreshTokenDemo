using System.Text.Json;

public class NormalFlow
{
    /* 1. Get refresh token
     * 2. Get access token basen on refresh token
     * 3. Access "open" endpoint with access token
     * 4. Login with access token
     * 5. Get new access token basen on refresh token
     * 6. Access restricted endpoint with new access token
     */


    public void Run()
    {
        var clientId = Guid.NewGuid();

        var httpClient = new HttpClient();

        // Get refresh token
        var initialRefreshToken = GetRefreshToken(httpClient, clientId);

        // Get access token
        var tokenPair = GetAccessToken(httpClient, initialRefreshToken);
    }

    private string GetRefreshToken(HttpClient client, Guid clientId)
    {
        var response = client.GetAsync($"https://localhost:5001/api/GetRefreshToken?clientId={clientId}").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }

    private TokenPair? GetAccessToken(HttpClient client, string refreshToken)
    {
        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + refreshToken);
        var response = client.GetAsync($"https://localhost:5001/api/GetAccessToken").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        return JsonSerializer.Deserialize<TokenPair>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private class TokenPair
    {
        public string RefreshToken { get; init; } = "";
        public string AccessToken { get; init; } = "";
    }
}
