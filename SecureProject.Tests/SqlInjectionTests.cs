using NUnit.Framework;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SecureProject.Tests
{
    public class SqlInjectionTests
    {
        private HttpClient _client;

        [SetUp]
        public void Setup()
        {
            _client = new HttpClient();
            _client.BaseAddress = new Uri("https://localhost:7001");
        }

        private async Task<string> GetJwtTokenAsync()
        {
            var loginContent = new StringContent("{\"username\":\"admin1\",\"password\":\"A!dm1n$2025!Strong\"}", Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("/api/auth/login", loginContent);
            var json = await response.Content.ReadAsStringAsync();
            var token = System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("token").GetString();
            return token;
        }

        [Test]
        public async Task CreateUser_WithSqlInjection_ReturnsBadRequest()
        {
            var token = await GetJwtTokenAsync();
            var payload = new StringContent("{" +
                "\"username\":\"hacker' OR 1=1;--\"," +
                "\"password\":\"password\"," +
                "\"name\":\"Evil\"," +
                "\"email\":\"evil@hacker.com\"," +
                "\"roles\":\"User\"}", Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/users") { Content = payload };
            request.Headers.Add("Authorization", $"Bearer {token}");
            var response = await _client.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        public async Task UpdateUser_WithSqlInjection_ReturnsBadRequest()
        {
            var token = await GetJwtTokenAsync();
            var payload = new StringContent("{" +
                "\"password\":\"password\"," +
                "\"name\":\"Robert'); DROP TABLE Users;--\"," +
                "\"email\":\"bad@user.com\"," +
                "\"roles\":\"User\"}", Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Put, "/api/users/user1") { Content = payload };
            request.Headers.Add("Authorization", $"Bearer {token}");
            var response = await _client.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [TearDown]
        public void TearDown()
        {
            _client.Dispose();
        }
    }
}
