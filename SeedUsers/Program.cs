using BCrypt.Net;

using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;

class User
{
	public required string Username { get; set; }
	public required string Password { get; set; }
	public string? Name { get; set; }
	public string? Email { get; set; }
	public string? Roles { get; set; } // Comma-separated roles
}

class Program
{
	static void Main(string[] args)
	{
		string connectionString = "Data Source=SeedUsers.db";
		using (var connection = new SqliteConnection(connectionString))
		{
			connection.Open();

			var tableCmd = connection.CreateCommand();
			tableCmd.CommandText = @"
				CREATE TABLE IF NOT EXISTS Users (
					Username TEXT PRIMARY KEY,
					Password TEXT NOT NULL,
					Name TEXT NOT NULL,
					Email TEXT NOT NULL,
					Roles TEXT NOT NULL
				);
			";
			tableCmd.ExecuteNonQuery();


			var users = new List<User>
			{
				new User { Username = "admin1", Password = BCrypt.Net.BCrypt.HashPassword("A!dm1n$2025!Strong"), Name = "Alice Admin", Email = "alice@secure.com", Roles = "Admin,Manager" },
				new User { Username = "manager1", Password = BCrypt.Net.BCrypt.HashPassword("M@nager#2025$Secure"), Name = "Bob Manager", Email = "bob@secure.com", Roles = "Manager" },
				new User { Username = "auditor1", Password = BCrypt.Net.BCrypt.HashPassword("Aud1t0r!2025@Safe"), Name = "Carol Auditor", Email = "carol@secure.com", Roles = "Auditor,Tester" },
				new User { Username = "tester1", Password = BCrypt.Net.BCrypt.HashPassword("T3st3r$2025!Pass"), Name = "Dave Tester", Email = "dave@secure.com", Roles = "Tester" },
				new User { Username = "user1", Password = BCrypt.Net.BCrypt.HashPassword("Us3r!2025#Good"), Name = "Eve User", Email = "eve@secure.com", Roles = "User" }
			};

			foreach (var user in users)
			{
				var insertCmd = connection.CreateCommand();
				insertCmd.CommandText = @"
					INSERT OR REPLACE INTO Users (Username, Password, Name, Email, Roles)
					VALUES ($username, $password, $name, $email, $roles);
				";
				insertCmd.Parameters.AddWithValue("$username", user.Username);
				insertCmd.Parameters.AddWithValue("$password", user.Password);
				insertCmd.Parameters.AddWithValue("$name", user.Name);
				insertCmd.Parameters.AddWithValue("$email", user.Email);
				insertCmd.Parameters.AddWithValue("$roles", user.Roles);
				insertCmd.ExecuteNonQuery();
			}

			Console.WriteLine("Database created and sample users inserted.");
		}
	}
}
