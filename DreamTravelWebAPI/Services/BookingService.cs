﻿// --------------------------------------------------------------
// Project: DreamTravelWebAPI
// Class: BookingService
// Author: Wijesooriya W.M.R.K
// Created: 10/13/2023
// Description: Service for managing bookings in the Dream Travel Web API
// --------------------------------------------------------------

using DreamTravelWebAPI.Models;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DreamTravelWebAPI.Services
{
    public class BookingService : IBookingService
    {
        private readonly IMongoCollection<Booking> _bookings;

        // Constructor: Initializes MongoDB settings and collection
        public BookingService(MongoDBSettings settings)
        {
            var client = new MongoClient(settings.ConnectionString);
            var database = client.GetDatabase(settings.DatabaseName);
            _bookings = database.GetCollection<Booking>("Bookings");
        }

        // Fetches all bookings
        public List<Booking> GetAll() => _bookings.Find(booking => true).ToList();

        // Fetches a booking by its BookingID
        public Booking GetByBookingID(string bookingID) => _bookings.Find<Booking>(booking => booking.BookingID == bookingID).FirstOrDefault();

        // Fetches bookings by NIC
        public IEnumerable<Booking> GetByNIC(string NIC) => _bookings.Find<Booking>(booking => booking.NIC == NIC).ToList();

        // Fetches bookings for a specific train
        public List<Booking> GetBookingsForTrain(string trainId)
        {
            return _bookings.Find(booking => booking.TrainID == trainId && booking.Status == Booking.StatusType.Reserved).ToList();
        }

        // Creates a new booking
        public Booking Create(Booking booking)
        {
            _bookings.InsertOne(booking);
            return booking;
        }

        // Updates an existing booking by BookingID
        public void Update(string bookingID, Booking bookingIn)
        {
            var originalBooking = GetByBookingID(bookingID);
            if (originalBooking == null)
            {
                throw new Exception("Booking not found.");
            }

            bookingIn.Id = originalBooking.Id;

            var filter = Builders<Booking>.Filter.Eq("BookingID", bookingID);
            _bookings.ReplaceOne(filter, bookingIn);
        }

        // Updates the status of a booking by BookingID
        public void UpdateStatus(string bookingID, Booking.StatusType status)
        {
            var booking = GetByBookingID(bookingID);
            if (booking == null)
            {
                throw new Exception($"Booking with ID {bookingID} not found.");
            }
            booking.Status = status;
            Update(bookingID, booking);
        }

        // Deletes a booking by BookingID
        public void Delete(string bookingID)
        {
            var originalBooking = GetByBookingID(bookingID);
            var filter = Builders<Booking>.Filter.Eq("Id", originalBooking.Id);
            _bookings.DeleteOne(filter);
        }

        // Checks if a booking exists by BookingID
        public bool Exists(string bookingID)
        {
            var filter = Builders<Booking>.Filter.Eq("BookingID", bookingID);
            return _bookings.CountDocuments(filter) > 0;
        }
    }
}
