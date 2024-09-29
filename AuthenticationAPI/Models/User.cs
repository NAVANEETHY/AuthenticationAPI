namespace AuthenticationAPI.Models
{
    public class User
    {
        public int UserId { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class SignInUser
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class EditUser
    {
        public string Name { get; set; }
    }
}
