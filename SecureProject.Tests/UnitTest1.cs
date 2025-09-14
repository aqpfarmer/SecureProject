
using System.Net.Http;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using NUnit.Framework;

namespace SecureProject.Tests
{
    public class ApiTests
    {
    private HttpClient _client;

        [SetUp]
        public void Setup()
        {
            _client = new HttpClient();
            _client.BaseAddress = new Uri("https://localhost:7001");
        }

        [Test]
        public async Task BadLogin_ReturnsUnauthorized()
        {
            var content = new StringContent("{\"username\":\"baduser\",\"password\":\"badpass\"}", Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("/api/auth/login", content);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        [Test]
        public async Task BadEndpoint_ReturnsNotFound()
        {
            var response = await _client.GetAsync("/api/doesnotexist");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        }

        private async Task<string> GetJwtTokenAsync()
        {
            var loginContent = new StringContent("{\"username\":\"admin1\",\"password\":\"A!dm1n$2025!Strong\"}", Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("/api/auth/login", loginContent);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();
            var token = System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("token").GetString();
            return token;
        }

        [Test]
        public async Task CreateUser_WithSqlInjection_ReturnsBadRequest()
        {
            var token = await GetJwtTokenAsync();
            var payload = new StringContent("{" +
                "\"username\":\"admin1; DROP TABLE Users;\"," +
                "\"password\":\"password\"," +
                "\"name\":\"<script>alert('xss')</script>\"," +
                "\"email\":\"bad@user.com\"," +
                "\"roles\":\"User\"}", Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/users") { Content = payload };
            request.Headers.Add("Authorization", $"Bearer {token}");
            var response = await _client.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        public async Task UpdateUser_WithScriptInjection_ReturnsBadRequest()
        {
            var token = await GetJwtTokenAsync();
            var payload = new StringContent("{" +
                "\"password\":\"password\"," +
                "\"name\":\"<script>alert('xss')</script>\"," +
                "\"email\":\"bad@user.com\"," +
                "\"roles\":\"User\"}", Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Put, "/api/users/admin1") { Content = payload };
            request.Headers.Add("Authorization", $"Bearer {token}");
            var response = await _client.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [TearDown]
        public void TearDown()
        {
            _client?.Dispose();
        }
    }
}
