function getRandomValue(array) {
  return array[Math.floor(Math.random() * array.length)];
}

function dsht() {
  const ms = getRandomValue([100, 150, 200, 300, 600, 500, 1000, 1400, 2500]);
  const ste = getRandomValue([1, 2, 3, 4, 5, 6, 7, 8]) === 8;
  if (ste) {
    const randomError = getRandomValue([
      "Internal Server Error",
      "Bad Gateway",
      "Service Unavailable",
      "Gateway Timeout",
    ]);
    throw new Error(randomError);
  }
  return new Promise((resolve, reject) => setTimeout(() => resolve(ms), ms));
}
module.exports = { dsht };
