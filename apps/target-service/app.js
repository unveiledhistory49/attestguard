const express = require('express');
const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());

// Health check endpoint
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Info endpoint
app.get('/api/info', (req, res) => {
  res.json({
    service: 'target-service',
    environment: process.env.NODE_ENV || 'production',
    secret_configured: Boolean(process.env.API_SECRET)
  });
});

// Diagnostic endpoint simulating workload operations
app.post('/api/workload', (req, res) => {
  const { task } = req.body;
  if (!task) {
    return res.status(400).json({ error: 'Task missing' });
  }
  console.log(`[TargetService] Executing workload task: ${task}`);
  res.json({ status: 'executed', task });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[TargetService] AttestGuard Workload running on port ${PORT}`);
});
