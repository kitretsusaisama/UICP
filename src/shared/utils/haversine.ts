const EARTH_RADIUS_KM = 6371;

export interface GeoCoordinate {
  lat: number;
  lon: number;
}

/**
 * Computes the great-circle distance between two geographic coordinates
 * using the Haversine formula.
 *
 * @param from - Origin coordinate { lat, lon } in decimal degrees
 * @param to   - Destination coordinate { lat, lon } in decimal degrees
 * @returns Distance in kilometres
 */
export function haversine(from: GeoCoordinate, to: GeoCoordinate): number {
  const toRad = (deg: number): number => (deg * Math.PI) / 180;

  const dLat = toRad(to.lat - from.lat);
  const dLon = toRad(to.lon - from.lon);

  const lat1 = toRad(from.lat);
  const lat2 = toRad(to.lat);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return EARTH_RADIUS_KM * c;
}
