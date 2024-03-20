 // Function to initialize and add the map
 function initMap() {
    // The location of Almaty
    var almatyLocation = { lat: 43.238949, lng: 76.889709 };
    // The map, centered at Almaty
    var map = new google.maps.Map(document.getElementById('map'), {
        zoom: 12, // Adjusted zoom level for city view
        center: almatyLocation
    });

    var locations = [
    { lat: 43.238949, lng: 76.889709, name: "Location 1" },
    { lat: 43.255058, lng: 76.912628, name: "Location 2" },
    { lat: 43.222014, lng: 76.851248, name: "Location 3" }
];

// Loop through the locations and place a marker for each one
locations.forEach(function(location) {
    var marker = new google.maps.Marker({
        position: {lat: location.lat, lng: location.lng},
        map: map,
        title: location.name // Optional: add a title/name to each marker
    });

  });

}