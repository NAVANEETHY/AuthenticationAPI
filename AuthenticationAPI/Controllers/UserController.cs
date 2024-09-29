using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Data;
using Microsoft.VisualBasic;
using System.Text;

namespace AuthenticationAPI.Controllers
{
    [Route("/[controller]/")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly TokenService _tokenService;
        private readonly PasswordService _passwordService;

        public UserController(IConfiguration configuration, TokenService tokenService, PasswordService passwordService)
        {
            _configuration = configuration;
            _tokenService = tokenService;
            _passwordService = passwordService;
        }

        [HttpGet]
        //Display a web page when the server is running
        public ContentResult Get()
        {
            string html = @"
            <html>
            <head>
                <title>Server Status</title>
                <style>
                    body {
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        font-family: Arial, sans-serif;
                    }
                    .message {
                        text-align: center;
                        font-size: 40px;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <div class='message'>
                    Server is running
                </div>
            </body>
            </html>";

            return new ContentResult
            {
                ContentType = "text/html",
                Content = html,
            };
        }

        [HttpPost]
        [Route("signup")]
        public async Task<string> CreateUser(User user)
        {
            string passwordHash;
            byte[] salt;
            try
            {
                passwordHash=_passwordService.HashPassword(user.Password, out salt);
                SqlConnection conn = new SqlConnection(_configuration.GetConnectionString("DefaultConnections"));
                await conn.OpenAsync();
                string SQL = "spCreateUser";
                SqlCommand cmd = new SqlCommand(SQL, conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@Name", user.Name);
                cmd.Parameters.AddWithValue("@Email", user.Email);
                cmd.Parameters.AddWithValue("@Hash", passwordHash);
                cmd.Parameters.AddWithValue("@Salt", salt);
                await cmd.ExecuteNonQueryAsync();
                conn.Close();
                return "User created";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        [HttpPost]
        [Route("signin")]
        public async Task<IActionResult> GetUser(SignInUser signInUser)
        {
            try
            {
                User user = new User();
                string TokenValue;
                string storedHash="";
                byte[] storedSalt=null;

                SqlConnection conn = new SqlConnection(_configuration.GetConnectionString("DefaultConnections"));
                await conn.OpenAsync();
                string SQL = "spGetHashSaltUser";
                SqlCommand cmd = new SqlCommand(SQL, conn);
                cmd.CommandType = CommandType.StoredProcedure;
                cmd.Parameters.AddWithValue("@Email", signInUser.Email);
                using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        storedHash = reader["Hash"].ToString();
                        storedSalt = (byte[])reader["Salt"]; //Encoding.UTF8.GetBytes  .ToString());
                    }
                }
                conn.Close();
                cmd.Dispose();

                if (_passwordService.VerifyPasswordHash(signInUser.Password, storedHash, storedSalt))
                {
                    conn = new SqlConnection(_configuration.GetConnectionString("DefaultConnections"));
                    conn.OpenAsync();
                    SQL = "spGetUser";
                    cmd = new SqlCommand(SQL, conn);
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@Email", signInUser.Email);
                    cmd.Parameters.AddWithValue("@Hash", storedHash);
                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            user.UserId = int.Parse(reader["UserId"].ToString());
                            user.Name = reader["Name"].ToString();
                            user.Email = reader["Email"].ToString();
                            user.Password = "";
                        }
                    }
                    conn.Close();
                    cmd.Dispose();

                     TokenValue = _tokenService.CreateToken(user);
                     return Ok(new { Token = TokenValue, User = user });
                    
                }
                return NoContent();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize(AuthenticationSchemes = "Scheme1")]
        [HttpPut]
        [Route("edit")]
        public IActionResult UpdateUser(EditUser editUser)
        {
            try
            {
                var AuthorizationHeader = HttpContext.Request.Headers["Authorization"].ToString();
                string token = AuthorizationHeader.StartsWith("Bearer ") ? AuthorizationHeader.Substring("Bearer ".Length).Trim() : null;
                var claims = _tokenService.ValidateToken(token);
                if (claims != null)
                {
                    string UserId = claims.FindFirst("UserId")?.Value;
                    SqlConnection conn = new SqlConnection(_configuration.GetConnectionString("DefaultConnections"));
                    conn.Open();
                    string SQL = "spUpdateUser";
                    SqlCommand cmd = new SqlCommand(SQL, conn);
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@UserId", int.Parse(UserId));
                    cmd.Parameters.AddWithValue("@Name", editUser.Name);
                    cmd.ExecuteNonQuery();
                    conn.Close();
                    return Ok("User details updated");
                }
                return Unauthorized("Token is not valid");
            }
            catch (Exception ex) 
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize(AuthenticationSchemes = "Scheme1")]
        [HttpDelete]
        [Route("delete")]
        public async Task<IActionResult> DeleteUser()
        {
            try
            {
                var AuthorizationHeader = HttpContext.Request.Headers["Authorization"].ToString();
                string token = AuthorizationHeader.StartsWith("Bearer ") ? AuthorizationHeader.Substring("Bearer ".Length).Trim() : null;
                var claims = _tokenService.ValidateToken(token);
                if (claims != null)
                {
                    string UserId = claims.FindFirst("UserId")?.Value;
                    SqlConnection conn = new SqlConnection(_configuration.GetConnectionString("DefaultConnections"));
                    await conn.OpenAsync();
                    string SQL = "spDeleteUser";
                    SqlCommand cmd = new SqlCommand(SQL, conn);
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@UserId", int.Parse(UserId));
                    await cmd.ExecuteNonQueryAsync();
                    conn.Close();
                    return Ok("User deleted");
                }
                return Unauthorized("Token is not valid");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
