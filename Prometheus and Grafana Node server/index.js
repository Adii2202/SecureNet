const express = require("express");
const client = require("prom-client"); // Metric Collection
const { dsht } = require("./util");
const responseTime = require("response-time");
const { createLogger, transports } = require("winston");
const LokiTransport = require("winston-loki");

const app = express();
const PORT = 8000;

// Logger setup
const logger = createLogger({
  transports: [
    new LokiTransport({
      host: "http://127.0.0.1:3100",
      onError: (err) => console.error("Loki Transport Error:", err),
    }),
  ],
});

// Collect default metrics
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ register: client.register });

// Define a histogram to measure request durations
const reqResTime = new client.Histogram({
  name: "http_request_duration_seconds",
  help: "Duration of HTTP requests in seconds",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// Apply response-time middleware to collect metrics
app.use(
  responseTime((req, res, time) => {
    reqResTime.labels(req.method, req.url, res.statusCode).observe(time / 1000); // Convert to seconds for Prometheus
  })
);

// Routes
app.get("/", (req, res) => {
  logger.info("/ route was called");
  return res.json({ message: "Hello World" });
});

app.get("/slow", async (req, res) => {
  try {
    logger.info("/SLOW route was called");
    const timeout = await dsht();
    return res.json({
      status: "success",
      message: `Heavy task took ${timeout} ms to complete`,
    });
  } catch (error) {
    logger.error("Error in /slow route: " + error.message);
    return res.status(500).json({ status: "error", message: error.message });
  }
});

// Endpoint for Prometheus to scrape metrics
app.get("/metrics", async (req, res) => {
  res.setHeader("Content-Type", client.register.contentType);
  const metrics = await client.register.metrics();
  res.send(metrics);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
