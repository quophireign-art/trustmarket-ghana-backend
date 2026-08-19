// backend/lib/maps.js
// "Maps & GPS" integration — geocoding addresses, calculating delivery
// distance/fees, and reverse-geocoding a rider's live coordinates for the
// Rider Live Tracking screen.
//
// Uses the Google Maps Platform. Enable the "Geocoding API" and "Distance
// Matrix API" on your Google Cloud project, then set GOOGLE_MAPS_API_KEY in
// backend/.env. https://console.cloud.google.com/google/maps-apis

function requireKey() {
  const key = process.env.GOOGLE_MAPS_API_KEY;
  if (!key) {
    const err = new Error(
      'Maps are not configured. Set GOOGLE_MAPS_API_KEY in backend/.env to enable geocoding & distance calculation.'
    );
    err.status = 501;
    throw err;
  }
  return key;
}

export async function geocodeAddress(address) {
  const key = requireKey();
  const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&region=gh&key=${key}`;
  const res = await fetch(url);
  const data = await res.json();
  if (data.status !== 'OK') {
    const err = new Error(`Geocoding failed: ${data.status}`);
    err.status = 502;
    throw err;
  }
  const top = data.results[0];
  return {
    formatted_address: top.formatted_address,
    lat: top.geometry.location.lat,
    lng: top.geometry.location.lng,
    place_id: top.place_id,
  };
}

export async function reverseGeocode(lat, lng) {
  const key = requireKey();
  const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${key}`;
  const res = await fetch(url);
  const data = await res.json();
  if (data.status !== 'OK') {
    const err = new Error(`Reverse geocoding failed: ${data.status}`);
    err.status = 502;
    throw err;
  }
  return { formatted_address: data.results[0]?.formatted_address || null };
}

/** Distance + ETA between a rider/pickup point and the delivery address (used for delivery fee + GPS tracking ETA). */
export async function distanceAndEta({ originLat, originLng, destLat, destLng }) {
  const key = requireKey();
  const url =
    `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${originLat},${originLng}` +
    `&destinations=${destLat},${destLng}&mode=driving&key=${key}`;
  const res = await fetch(url);
  const data = await res.json();
  const el = data.rows?.[0]?.elements?.[0];
  if (data.status !== 'OK' || !el || el.status !== 'OK') {
    const err = new Error(`Distance calculation failed: ${data.status || el?.status}`);
    err.status = 502;
    throw err;
  }
  return {
    distance_km: el.distance.value / 1000,
    distance_text: el.distance.text,
    duration_seconds: el.duration.value,
    duration_text: el.duration.text,
  };
}

/** Simple delivery-fee formula: base fare + per-km rate (tune to your market). */
export function calculateDeliveryFee(distanceKm) {
  const BASE_FARE = 5; // GH₵
  const PER_KM = 2.5; // GH₵
  return Math.round((BASE_FARE + distanceKm * PER_KM) * 100) / 100;
}
