using DreamTravelWebAPI.Models;
using System.Collections.Generic;

namespace DreamTravelWebAPI.Services
{
    public interface IUserService
    {
        List<User> GetAll();
        User GetByNic(string nic);
        User Create(User user);
        void Update(string nic, User user);
        void Delete(string nic);
        bool Exists(string nic);
        bool ValidatePassword(User user, string password);

        void HashPassword(User user);
        void Activate(string nic);
        void Deactivate(string nic);
    }
}
