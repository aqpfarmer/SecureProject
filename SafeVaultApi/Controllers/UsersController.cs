using Microsoft.AspNetCore.Mvc;
using SecureProject.Shared.Models;
using System.Collections.Generic;
using Microsoft.Data.Sqlite;
using System.Data;

namespace SafeVaultApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Microsoft.AspNetCore.Authorization.Authorize]
    public class UsersController : ControllerBase
    {
        private readonly ILogger<UsersController> _logger;

        public UsersController(ILogger<UsersController> logger)
        {
            _logger = logger;
        }

        private bool IsInputSafe(string input, string fieldName = "")
        {
            if (string.IsNullOrWhiteSpace(input)) {
                _logger?.LogWarning($"Blocked empty or whitespace input for field '{fieldName}' at {DateTime.UtcNow}");
                return false;
            }
            // Basic checks for SQL/script injection/XSS
            string lowered = input.ToLower();
            if (lowered.Contains("select") || lowered.Contains("insert") || lowered.Contains("delete") || lowered.Contains("update") ||
                lowered.Contains("drop") || lowered.Contains("--") || lowered.Contains(";") || lowered.Contains("<script") || lowered.Contains("</script>"))
            {
                _logger?.LogWarning($"Malicious input detected in field '{fieldName}': '{input}' at {DateTime.UtcNow}");
                return false;
            }
            return true;
        }
    
    private readonly string _connectionString = "Data Source=../SeedUsers.db";

        private void EnsureTable()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Username TEXT PRIMARY KEY,
                    Password TEXT NOT NULL,
                    Name TEXT NOT NULL,
                    Email TEXT NOT NULL,
                    Roles TEXT NOT NULL
                );
            ";
            cmd.ExecuteNonQuery();
        }

        [HttpGet]
        public ActionResult<IEnumerable<User>> GetAll()
        {
            EnsureTable();
            var users = new List<User>();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Username, Password, Name, Email, Roles FROM Users";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                users.Add(new User
                {
                    Username = reader.GetString(0),
                    Password = reader.GetString(1),
                    Name = reader.GetString(2),
                    Email = reader.GetString(3),
                    Roles = reader.GetString(4)
                });
            }
            return users;
        }

        [HttpGet("{username}")]
        public ActionResult<User> Get(string username)
        {
            EnsureTable();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT Username, Password, Name, Email, Roles FROM Users WHERE Username = $username";
            cmd.Parameters.AddWithValue("$username", username);
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Username = reader.GetString(0),
                    Password = reader.GetString(1),
                    Name = reader.GetString(2),
                    Email = reader.GetString(3),
                    Roles = reader.GetString(4)
                };
            }
            return NotFound();
        }

        [HttpPost]
        public ActionResult<User> Create(User user)
        {
            EnsureTable();
            // Validate input
            if (!IsInputSafe(user.Username, "Username") || !IsInputSafe(user.Password, "Password") || !IsInputSafe(user.Name, "Name") || !IsInputSafe(user.Email, "Email") || !IsInputSafe(user.Roles, "Roles"))
            {
                _logger?.LogWarning($"Blocked user creation due to malicious input. Username: {user.Username}, Name: {user.Name}, Email: {user.Email}, Roles: {user.Roles} at {DateTime.UtcNow}");
                return BadRequest("Malicious input detected.");
            }
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Users (Username, Password, Name, Email, Roles)
                VALUES ($username, $password, $name, $email, $roles)
            ";
            cmd.Parameters.AddWithValue("$username", user.Username);
            cmd.Parameters.AddWithValue("$password", user.Password);
            cmd.Parameters.AddWithValue("$name", user.Name);
            cmd.Parameters.AddWithValue("$email", user.Email);
            cmd.Parameters.AddWithValue("$roles", user.Roles);
            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // UNIQUE constraint failed
            {
                return Conflict();
            }
            return CreatedAtAction(nameof(Get), new { username = user.Username }, user);
        }

        [HttpPut("{username}")]
        public IActionResult Update(string username, User updatedUser)
        {
            EnsureTable();
            // Validate input
            if (!IsInputSafe(username, "Username") || !IsInputSafe(updatedUser.Password, "Password") || !IsInputSafe(updatedUser.Name, "Name") || !IsInputSafe(updatedUser.Email, "Email") || !IsInputSafe(updatedUser.Roles, "Roles"))
            {
                _logger?.LogWarning($"Blocked user update due to malicious input. Username: {username}, Name: {updatedUser.Name}, Email: {updatedUser.Email}, Roles: {updatedUser.Roles} at {DateTime.UtcNow}");
                return BadRequest("Malicious input detected.");
            }
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                UPDATE Users SET Password = $password, Name = $name, Email = $email, Roles = $roles
                WHERE Username = $username
            ";
            cmd.Parameters.AddWithValue("$password", updatedUser.Password);
            cmd.Parameters.AddWithValue("$name", updatedUser.Name);
            cmd.Parameters.AddWithValue("$email", updatedUser.Email);
            cmd.Parameters.AddWithValue("$roles", updatedUser.Roles);
            cmd.Parameters.AddWithValue("$username", username);
            int rows = cmd.ExecuteNonQuery();
            if (rows == 0) return NotFound();
            return NoContent();
        }

        [HttpDelete("{username}")]
        public IActionResult Delete(string username)
        {
            EnsureTable();
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = "DELETE FROM Users WHERE Username = $username";
            cmd.Parameters.AddWithValue("$username", username);
            int rows = cmd.ExecuteNonQuery();
            if (rows == 0) return NotFound();
            return NoContent();
        }
    }
}
