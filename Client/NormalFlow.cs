using System.Net.Http.Json;
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
        var accessToken = GetAccessToken(httpClient, initialRefreshToken);

        // Call "open" endpoint
        CallOpenEndpoint(httpClient, accessToken);

        // Login in as user
        accessToken = LoginAsUser(httpClient, accessToken);

        // Call restricted endpoint
        CallRestrictedEndpoint(httpClient, accessToken);
    }

    private Token GetRefreshToken(HttpClient client, Guid clientId)
    {
        Console.WriteLine("Getting refresh token");
        var response = client.GetAsync($"https://localhost:5001/api/GetRefreshToken?clientId={clientId}").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        var token = JsonSerializer.Deserialize<Token>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return token ?? new Token();
    }

    private Token GetAccessToken(HttpClient client, Token token)
    {
        Console.WriteLine("Getting access token");
        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token.RefreshToken);
        var response = client.GetAsync($"https://localhost:5001/api/GetAccessToken").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        var newToken = JsonSerializer.Deserialize<Token>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return newToken ?? new Token();
    }

    private void CallOpenEndpoint(HttpClient client, Token token)
    {
        Console.WriteLine("Calling open endpoint");
        client.DefaultRequestHeaders.Remove("Authorization");
        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token.AccessToken);
        var response = client.GetAsync($"https://localhost:5001/api/SomeOpenEndpoint").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var message = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Console.WriteLine(message);
    }

    private Token LoginAsUser(HttpClient client, Token token)
    {
        Console.WriteLine("Login as user");
        client.DefaultRequestHeaders.Remove("Authorization");
        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token.AccessToken);
        var response = client.PostAsJsonAsync($"https://localhost:5001/api/Login", new { Username = "Tarzan", Password = "ooohiooh" }).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        var newToken = JsonSerializer.Deserialize<Token>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return newToken ?? new Token();
    }

    private void CallRestrictedEndpoint(HttpClient client, Token token)
    {
        Console.WriteLine("Calling restricted endpoint");
        client.DefaultRequestHeaders.Remove("Authorization");
        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token.AccessToken);
        var response = client.GetAsync($"https://localhost:5001/api/SomeRestrictedEndpoint").GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();
        var message = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Console.WriteLine(message);
    }

    private class Token
    {
        public string RefreshToken { get; init; } = "";
        public string AccessToken { get; init; } = "";
    }
}
