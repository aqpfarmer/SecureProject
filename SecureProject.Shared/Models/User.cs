using System.Text.Json.Serialization;

namespace SecureProject.Shared.Models
{
    public class User
    {
        [JsonPropertyName("username")]
        public string? Username { get; set; }
        [JsonPropertyName("password")]
        public string? Password { get; set; }
        [JsonPropertyName("name")]
        public string? Name { get; set; }
        [JsonPropertyName("email")]
        public string? Email { get; set; }
        [JsonPropertyName("roles")]
        public string? Roles { get; set; }
    }
}
