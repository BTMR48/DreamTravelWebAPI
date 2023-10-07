using System.ComponentModel.DataAnnotations;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace DreamTravelWebAPI.Models
{
    
        public class User
        {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        [Required]
            [StringLength(12, ErrorMessage = "NIC length should be 12 characters.")]
            public string NIC { get; set; }

            [Required]
            [EnumDataType(typeof(UserRole))]
            public UserRole Role { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "Password length should be between 6 and 100 characters.", MinimumLength = 6)]
            public string Password { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            public bool IsActive { get; set; }
        }

        public enum UserRole
        {
            Backoffice,
            TravelAgent,
            Traveler
        }
    }



