using System.Collections.Generic;
using System.Linq;
using DreamTravelWebAPI.Models;
using MongoDB.Driver;

namespace DreamTravelWebAPI.Services
{
    public class UserService : IUserService
    {
        private readonly IMongoCollection<User> _users;

        public UserService(MongoDBSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _users = database.GetCollection<User>("Users");
        }

        public List<User> GetAll() => _users.Find(user => true).ToList();

        public User GetByNic(string nic) => _users.Find<User>(user => user.NIC == nic).FirstOrDefault();

        public User Create(User user)
        {
            _users.InsertOne(user);
            return user;
        }

        public void Update(string nic, User userIn) => _users.ReplaceOne(user => user.NIC == nic, userIn);

        public void Delete(string nic) => _users.DeleteOne(user => user.NIC == nic);

        public bool Exists(string nic) => _users.CountDocuments(user => user.NIC == nic) > 0;

        public bool ValidatePassword(User user, string password)
        {
            return BCrypt.Net.BCrypt.Verify(password, user.Password);
        }

        public void HashPassword(User user)
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
        }

        public void Activate(string nic)
        {
            var user = GetByNic(nic);
            if (user == null)
                return;

            user.IsActive = true;
            Update(nic, user);
        }

        // Deactivate a user
        public void Deactivate(string nic)
        {
            var user = GetByNic(nic);
            if (user == null)
                return;

            user.IsActive = false;
            Update(nic, user);
        }
    }
}
