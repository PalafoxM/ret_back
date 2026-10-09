const { RecaptchaEnterpriseServiceClient } = require("@google-cloud/recaptcha-enterprise");

const PROJECT_ID = String(process.env.RECAPTCHA_PROJECT_ID || "ret-secturi").trim();
const SITE_KEY = String(process.env.RECAPTCHA_SITE_KEY || "6LcEdectAAAAALktcjOF5fQ43mCN3ejx22DdMz9e").trim();
const parsedMinimumScore = Number.parseFloat(process.env.RECAPTCHA_MIN_SCORE || "0.5");
const MINIMUM_SCORE = Number.isFinite(parsedMinimumScore) ? Math.min(1, Math.max(0, parsedMinimumScore)) : 0.5;
const client = new RecaptchaEnterpriseServiceClient();

const assessLogin = async ({ token, ipAddress, userAgent }) => {
  if (!PROJECT_ID || !SITE_KEY || !token) return { valid: false, score: 0, reasons: ["MISSING_CONFIGURATION_OR_TOKEN"] };
  const [assessment] = await client.createAssessment({
    parent: client.projectPath(PROJECT_ID),
    assessment: {
      event: {
        token,
        siteKey: SITE_KEY,
        expectedAction: "LOGIN",
        userIpAddress: String(ipAddress || "").slice(0, 64),
        userAgent: String(userAgent || "").slice(0, 512),
      },
    },
  });
  const tokenValid = assessment.tokenProperties?.valid === true;
  const actionValid = assessment.tokenProperties?.action === "LOGIN";
  const score = Number(assessment.riskAnalysis?.score || 0);
  return {
    valid: tokenValid && actionValid && score >= MINIMUM_SCORE,
    score,
    reasons: assessment.riskAnalysis?.reasons || [],
  };
};

module.exports = { assessLogin };
