using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace TokenManagement
{
    public class TokenManagerConfig
    {
        public string ClientId { get; set; }
        public string Authority { get; set; }
        public string[] Scopes { get; set; }
        public string RedirectUri { get; set; }

        public static TokenManagerConfig Default => new TokenManagerConfig
        {
            ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            Authority = "https://login.microsoftonline.com/common",
            Scopes = new[] { "https://graph.microsoft.com/.default" },
            RedirectUri = "http://localhost"
        };
    }

    public class TokenInfo
    {
        public string AccessToken { get; set; }
        public string TenantId { get; set; }
        public string Username { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string[] Permissions { get; set; }
    }

    public class TokenManager
    {
        private readonly IPublicClientApplication _app;
        private readonly TokenManagerConfig _config;
        private const string TokenEnvVariable = "MS_GRAPH_ACCESS_TOKEN";
        private const string TokenExpiryEnvVariable = "MS_GRAPH_TOKEN_EXPIRY";

        public TokenManager(TokenManagerConfig config = null)
        {
            _config = config ?? TokenManagerConfig.Default;
            _app = PublicClientApplicationBuilder.Create(_config.ClientId)
                .WithAuthority(_config.Authority)
                .WithRedirectUri(_config.RedirectUri)
                .Build();
        }

        public async Task<TokenInfo> GetTokenAsync()
        {
            try
            {
                // Check for stored token
                var storedToken = GetStoredToken();
                if (!string.IsNullOrEmpty(storedToken) && IsTokenValid(storedToken))
                {
                    Console.WriteLine("Using valid stored token.");
                    return ParseTokenInfo(storedToken);
                }

                // Try silent refresh
                var accounts = await _app.GetAccountsAsync();
                if (accounts.Any())
                {
                    try
                    {
                        Console.WriteLine("Attempting silent token refresh...");
                        var result = await _app.AcquireTokenSilent(_config.Scopes, accounts.First()).ExecuteAsync();
                        StoreToken(result.AccessToken);
                        return ParseTokenInfo(result.AccessToken);
                    }
                    catch (MsalUiRequiredException)
                    {
                        Console.WriteLine("Silent refresh failed. Need interactive login.");
                    }
                }

                // Interactive login
                var authResult = await _app.AcquireTokenWithDeviceCode(_config.Scopes, deviceCodeCallback =>
                {
                    Console.WriteLine($"\nGo to: {deviceCodeCallback.VerificationUrl}");
                    Console.WriteLine($"Enter this code: {deviceCodeCallback.UserCode}");
                    Console.WriteLine($"\nPolling for authentication every {deviceCodeCallback.Interval} seconds...");
                    return Task.CompletedTask;
                }).ExecuteAsync();

                StoreToken(authResult.AccessToken);
                return ParseTokenInfo(authResult.AccessToken);
            }
            catch (Exception ex)
            {
                throw new TokenManagementException("Error acquiring token", ex);
            }
        }

        private TokenInfo ParseTokenInfo(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            return new TokenInfo
            {
                AccessToken = token,
                TenantId = jwtToken.Claims.FirstOrDefault(c => c.Type == "tid")?.Value ?? "Unknown",
                Username = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                    ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "upn")?.Value
                    ?? "Unknown",
                ExpiresAt = jwtToken.ValidTo,
                Permissions = jwtToken.Claims
                    .FirstOrDefault(c => c.Type == "scp")?.Value
                    .Split(' ')
                    .OrderBy(s => s)
                    .ToArray() ?? Array.Empty<string>()
            };
        }

        private void StoreToken(string token)
        {
            if (string.IsNullOrEmpty(token)) return;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                Environment.SetEnvironmentVariable(TokenEnvVariable, token, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable(TokenExpiryEnvVariable,
                    jwtToken.ValidTo.ToString("o"), EnvironmentVariableTarget.User);
            }
            catch (Exception ex)
            {
                throw new TokenManagementException("Error storing token", ex);
            }
        }

        private string GetStoredToken()
        {
            return Environment.GetEnvironmentVariable(TokenEnvVariable, EnvironmentVariableTarget.User);
        }

        private bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token)) return false;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);
                return jwtToken.ValidTo > DateTime.UtcNow.AddMinutes(5);
            }
            catch
            {
                return false;
            }
        }
    }

    public class TokenManagementException : Exception
    {
        public TokenManagementException(string message, Exception innerException = null)
            : base(message, innerException)
        {
        }
    }

    public class ConsoleHelper
    {
        public static void PrintProgramHeader()
        {
            Console.Clear(); // Clear the console
            var currentColor = Console.ForegroundColor;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine("                     Azure Privesc Check                       ");
            Console.WriteLine("═══════════════════════════════════════════════════════════════");

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"Version: 1.0.0");
            Console.WriteLine($"Author:  Warren Butterworth");
            Console.WriteLine($"Date:    {DateTime.Now:yyyy-MM-dd}");
            Console.WriteLine("═══════════════════════════════════════════════════════════════\n");

            Console.ForegroundColor = currentColor; // Restore original color
        }
    }

    // Current working on implementing GraphAPI calls HERE
    public static class GraphApiHelper
    {
        public static async Task FetchGraphAppDataAsync(string accessToken)
        {
            using (HttpClient client = new HttpClient())
            { 
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            string graphEndpoint = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy";
            HttpResponseMessage response = await client.GetAsync(graphEndpoint);

            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = await response.Content.ReadAsStringAsync();
                using (JsonDocument doc = JsonDocument.Parse(jsonResponse))
                {
                    JsonElement root = doc.RootElement;

                    Console.WriteLine("\nMicrosoft App Registration Policy:");
                    Console.WriteLine(new string('═', 60));

                    if (root.TryGetProperty("defaultUserRolePermissions", out JsonElement permissions))
                    {
                        PrintPolicyDetails(permissions);
                    }
                    else
                    {
                        Console.WriteLine("No policy details found.");
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nError fetching user data: {response.StatusCode}");
                Console.ResetColor();
            }
        }
    }

        private static void PrintPolicyDetails(JsonElement permissions)
        {
            PrintBooleanProperty(permissions, "allowedToCreateApps", "Allowed to Create Apps");
            PrintBooleanProperty(permissions, "allowedToCreateSecurityGroups", "Allowed to Create Security Groups");
            PrintBooleanProperty(permissions, "allowedToCreateTenants", "Allowed to Create Tenants");
            PrintBooleanProperty(permissions, "allowedToReadBitlockerKeysForOwnedDevice", "Allowed to Read Bitlocker Keys for Owned Device");
            PrintBooleanProperty(permissions, "allowedToReadOtherUsers", "Allowed to Read Other Users");

            if (permissions.TryGetProperty("permissionGrantPoliciesAssigned", out JsonElement policies) && policies.ValueKind == JsonValueKind.Array)
            {
                Console.WriteLine("\nPermission Grant Policies Assigned:");
                foreach (JsonElement policy in policies.EnumerateArray())
                {
                    Console.WriteLine($"  - {policy.GetString()}");
                }
            }
        }

        private static void PrintBooleanProperty(JsonElement element, string propertyName, string displayName)
        {
            if (element.TryGetProperty(propertyName, out JsonElement value) && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
            {
                Console.WriteLine($"{displayName}: {(value.GetBoolean() ? "Yes" : "No")}");
            }
        }

        // **Guest Invite Check Added Here**
        public static async Task CheckUserGuestInvitePermissionsAsync(string accessToken, string userId)
        {
            using (HttpClient client = new HttpClient()) 
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                try
                {
                    HttpResponseMessage response = await client.GetAsync($"https://graph.microsoft.com/v1.0/users/{userId}/memberOf");
                    if (!response.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Failed to fetch user roles: {response.StatusCode}");
                        return;
                    }

                    string jsonResponse = await response.Content.ReadAsStringAsync();

                    JsonElement rolesElement;
                    using (JsonDocument doc = JsonDocument.Parse(jsonResponse))
                    {
                        if (!doc.RootElement.TryGetProperty("value", out JsonElement tempRoles) || tempRoles.ValueKind != JsonValueKind.Array)
                        {
                            Console.WriteLine("Error: The expected 'value' property is not an array.");
                            return;
                        }
                        rolesElement = tempRoles.Clone(); 
                    } 

                    bool canInvite = false;
                    foreach (JsonElement role in rolesElement.EnumerateArray())
                    {
                        if (role.TryGetProperty("roleTemplateId", out JsonElement roleId))
                        {
                            string roleTemplateId = roleId.GetString();
                            if (roleTemplateId == "62e90394-69f5-4237-9190-012177145e10" ||  // Global Administrator
                                roleTemplateId == "fe930be7-5e62-47db-91af-98c3a49a38b1" ||  // User Administrator
                                roleTemplateId == "95e79109-95c0-4d8e-aee3-d01accf2d47b")   // Guest Inviter
                            {
                                canInvite = true;
                                break;
                            }
                        }
                    }

                    Console.WriteLine("\nUser Guest Invite Permissions:");
                    Console.WriteLine(new string('═', 60));
                    Console.WriteLine(canInvite ? " This user **can** invite guests." : "This user **cannot** invite guests.");
                    Console.WriteLine(new string('═', 60));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception: {ex.Message}");
                }
            }
        }


        class Program
        {
            static async Task Main()
            {
                try
                {
                    ConsoleHelper.PrintProgramHeader();

                    Console.WriteLine("Initializing authentication process...\n");
                    var tokenManager = new TokenManager();
                    var tokenInfo = await tokenManager.GetTokenAsync();

                    // Display token information
                    Console.WriteLine("\nAuthentication Successful!");
                    Console.WriteLine("═══════════════════════════════════════════════════════════════");
                    Console.WriteLine($"Tenant ID: {tokenInfo.TenantId}");
                    Console.WriteLine($"User: {tokenInfo.Username}");
                    Console.WriteLine($"Access Token: {tokenInfo.AccessToken.Substring(0, 50)}... (truncated)");
                    Console.WriteLine($"Token Expires: {tokenInfo.ExpiresAt} UTC");

                    Console.WriteLine("\nGranted Permissions (Scopes):");
                    Console.WriteLine("═══════════════════════════════════════════════════════════════");
                    foreach (var permission in tokenInfo.Permissions)
                    {
                        Console.WriteLine($"• {permission}");
                    }

                    // Perform Microsoft Graph API lookup
                    await GraphApiHelper.FetchGraphAppDataAsync(tokenInfo.AccessToken);

                    // **Run the Guest Invite Check**
                    await GraphApiHelper.CheckUserGuestInvitePermissionsAsync(tokenInfo.AccessToken, tokenInfo.Username);
                }
                catch (TokenManagementException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\nToken management error: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"Details: {ex.InnerException.Message}");
                    }
                    Console.ResetColor();
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\nUnexpected error: {ex.Message}");
                    Console.ResetColor();
                }
            }
        }
    }
}