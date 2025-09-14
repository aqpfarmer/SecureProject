using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;
using System.Collections.Generic;

namespace SafeVaultApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        // Simple in-memory store for refresh tokens (replace with DB for production)
        private static Dictionary<string, string> RefreshTokens = new();

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
                return Unauthorized();

            // Validate against database
            string connectionString = "Data Source=../SeedUsers.db";
            using var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString);
            connection.Open();
            // Ensure table exists
            var ensureCmd = connection.CreateCommand();
            ensureCmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Username TEXT PRIMARY KEY,
                    Password TEXT NOT NULL,
                    Name TEXT NOT NULL,
                    Email TEXT NOT NULL,
                    Roles TEXT NOT NULL
                );
            ";
            ensureCmd.ExecuteNonQuery();

            var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Password, Roles FROM Users WHERE Username = $username";
            cmd.Parameters.AddWithValue("$username", request.Username);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return Unauthorized();

            var hashedPassword = reader.GetString(0);
            var roles = reader.GetString(1);
            if (!BCrypt.Net.BCrypt.Verify(request.Password, hashedPassword))
                return Unauthorized();

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, request.Username),
                new Claim(ClaimTypes.Role, roles)
            };

            var signingKey = HttpContext.RequestServices.GetService<IConfiguration>()?["Jwt:IssuerSigningKey"];
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            // Generate refresh token (random string)
            var refreshToken = Guid.NewGuid().ToString() + Guid.NewGuid().ToString();
            RefreshTokens[request.Username] = refreshToken;

            return Ok(new {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                refreshToken
            });
        }

        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.RefreshToken))
                return Unauthorized();

            // Validate refresh token
            if (!RefreshTokens.TryGetValue(request.Username, out var storedToken) || storedToken != request.RefreshToken)
                return Unauthorized();

            // Get user roles from DB
            string connectionString = "Data Source=../SeedUsers.db";
            using var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Roles FROM Users WHERE Username = $username";
            cmd.Parameters.AddWithValue("$username", request.Username);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return Unauthorized();
            var roles = reader.GetString(0);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, request.Username),
                new Claim(ClaimTypes.Role, roles)
            };
            var signingKey = HttpContext.RequestServices.GetService<IConfiguration>()?["Jwt:IssuerSigningKey"];
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            // Optionally rotate refresh token
            var newRefreshToken = Guid.NewGuid().ToString() + Guid.NewGuid().ToString();
            RefreshTokens[request.Username] = newRefreshToken;

            return Ok(new {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                refreshToken = newRefreshToken
            });
        }
    }
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class RefreshRequest
{
    public string Username { get; set; }
    public string RefreshToken { get; set; }
}
