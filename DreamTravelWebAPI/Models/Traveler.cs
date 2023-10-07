using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace DreamTravelWebAPI.Models
{
    public class Traveler
    {
        [BsonRepresentation(BsonType.ObjectId)]
        public string NIC { get; set; }  // Using NIC as the unique identifier for travelers

        public string Name { get; set; }

        public DateTime DateOfBirth { get; set; }

        public bool IsActive { get; set; }
    }

}
