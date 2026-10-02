module.exports = {
   // If you want to debug regression tests, you will need the following.
   zapHostName: "192.168.56.20",
   zapPort: "8080",
   // Required from Zap 2.4.1. Set in Zap Options -> API. Read from the
   // ZAP_API_KEY environment variable so the key is never committed (CWE-798).
   zapApiKey: process.env.ZAP_API_KEY || "",
   zapApiFeedbackSpeed: 5000 // Milliseconds.
};
