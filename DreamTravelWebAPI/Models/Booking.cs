using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace DreamTravelWebAPI.Models
{
    public class Booking
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string BookingID { get; set; }

        public string NIC { get; set; }  // NIC of the traveler making the booking

        public string TrainID { get; set; }  // Identifier for the train being booked

        public DateTime ReservationDate { get; set; }  // The date the traveler is reserving for

        public enum BookingStatus
        {
            Active,
            Cancelled,
            // ... any other statuses you might have
        }

        public BookingStatus Status { get; set; }
    }

}
