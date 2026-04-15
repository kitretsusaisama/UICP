import { haversine } from './haversine';

describe('haversine', () => {
  // Known city-pair distances (approximate, within ±1%)
  const NYC = { lat: 40.7128, lon: -74.006 };
  const LONDON = { lat: 51.5074, lon: -0.1278 };
  const TOKYO = { lat: 35.6762, lon: 139.6503 };
  const SYDNEY = { lat: -33.8688, lon: 151.2093 };
  const PARIS = { lat: 48.8566, lon: 2.3522 };

  it('NYC → London ≈ 5570 km', () => {
    const dist = haversine(NYC, LONDON);
    expect(dist).toBeGreaterThan(5540);
    expect(dist).toBeLessThan(5600);
  });

  it('NYC → Tokyo ≈ 10838 km', () => {
    const dist = haversine(NYC, TOKYO);
    expect(dist).toBeGreaterThan(10800);
    expect(dist).toBeLessThan(10900);
  });

  it('London → Paris ≈ 340 km', () => {
    const dist = haversine(LONDON, PARIS);
    expect(dist).toBeGreaterThan(330);
    expect(dist).toBeLessThan(350);
  });

  it('Sydney → Tokyo ≈ 7823 km', () => {
    const dist = haversine(SYDNEY, TOKYO);
    expect(dist).toBeGreaterThan(7780);
    expect(dist).toBeLessThan(7870);
  });

  it('returns 0 for same coordinates', () => {
    expect(haversine(NYC, NYC)).toBeCloseTo(0, 5);
  });

  it('is symmetric: dist(A, B) === dist(B, A)', () => {
    const ab = haversine(NYC, LONDON);
    const ba = haversine(LONDON, NYC);
    expect(ab).toBeCloseTo(ba, 5);
  });

  it('returns positive distance for antipodal points', () => {
    // Antipodal points are ~20015 km apart (half Earth circumference)
    const north = { lat: 90, lon: 0 };
    const south = { lat: -90, lon: 0 };
    const dist = haversine(north, south);
    expect(dist).toBeGreaterThan(20000);
    expect(dist).toBeLessThan(20020);
  });

  it('detects impossible travel: NYC → London in 1 hour exceeds 900 km/h', () => {
    const distKm = haversine(NYC, LONDON);
    const speedKmh = distKm / 1; // 1 hour
    expect(speedKmh).toBeGreaterThan(900);
  });
});
