/**
 * Returns the input points array if it contains 3 or more points,
 * otherwise returns null. Required because d3.polygonHull returns
 * null on fewer than 3 points.
 * @param points - Array of [x, y] coordinate pairs
 * @returns The original array if valid for hull computation, otherwise null
 */
export function safeHull(points: [number, number][]): [number, number][] | null {
  return points.length >= 3 ? points : null;
}
