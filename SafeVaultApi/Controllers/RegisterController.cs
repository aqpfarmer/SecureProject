using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureProject.Shared.Models;
using Microsoft.Data.Sqlite;
using System.Text.RegularExpressions;

namespace SafeVaultApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegisterController : ControllerBase
    {
        private readonly string _connectionString = "Data Source=../SeedUsers.db";

        private bool IsPasswordStrong(string password)
        {
            // At least 12 chars, upper, lower, digit, special
            return password.Length >= 12 &&
                Regex.IsMatch(password, "[A-Z]") &&
                Regex.IsMatch(password, "[a-z]") &&
                Regex.IsMatch(password, "[0-9]") &&
                Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':"",.<>/?]"); // double quote escaped as ""
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Register(User user)
        {
            if (string.IsNullOrWhiteSpace(user.Username) ||
                string.IsNullOrWhiteSpace(user.Password) ||
                string.IsNullOrWhiteSpace(user.Name) ||
                string.IsNullOrWhiteSpace(user.Email))
            {
                return BadRequest("All fields are required.");
            }
            if (string.IsNullOrWhiteSpace(user.Roles))
            {
                user.Roles = "User";
            }
            if (!IsPasswordStrong(user.Password))
            {
                return BadRequest("Password is not strong enough.");
            }
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO Users (Username, Password, Name, Email, Roles)
                VALUES ($username, $password, $name, $email, $roles)
            ";
            cmd.Parameters.AddWithValue("$username", user.Username);
            cmd.Parameters.AddWithValue("$password", BCrypt.Net.BCrypt.HashPassword(user.Password));
            cmd.Parameters.AddWithValue("$name", user.Name);
            cmd.Parameters.AddWithValue("$email", user.Email);
            cmd.Parameters.AddWithValue("$roles", user.Roles);
            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
            {
                return Conflict("Username already exists.");
            }
            return Ok("User registered successfully.");
        }
    }
}
