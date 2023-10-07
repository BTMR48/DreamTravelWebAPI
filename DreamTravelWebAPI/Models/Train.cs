using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace DreamTravelWebAPI.Models
{
    public class Train
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string TrainID { get; set; }

        public string Name { get; set; }

        public string Schedule { get; set; }  // This could be a complex type or string representation of the schedule

        public bool IsActive { get; set; }
    }

}
