// server/src/riskEngine.ts
export type Telemetry = {
  windowBlurCount?: number;
  pasteDetected?: boolean;
  keystrokeFlightMs?: number;
  mouseCurvature?: number;
};

export type RiskResult = {
  sanitizedText: string;
  overallRiskScore: number;
  threatVector:
    | "PROMPT_INJECTION"
    | "REMOTE_COERCION"
    | "INVOICE_PHISHING"
    | "FF_PURCHASE_TRAP"
    | "BOT_CARDING_WAVE"
    | "CLEAN_TRANSACTION";
  shapAttributions: Record<string, number>;
};

export function evaluateRisk(rawText: string, telemetry: Telemetry = {}): RiskResult {
  // Strip zero-width characters + neutralize common jailbreaks + homographs
  const sanitizedText = rawText
    .replace(/[\u200B-\u200D\uFEFF\u202A-\u202E]/g, "")
    .replace(/paypaI\.com/gi, "paypal.com [HOMOGRAPH_BLOCKED]")
    .replace(/\[(SYSTEM|INST|OVERRIDE)[^\]]*\]/gi, "[REDACTED_JAILBREAK_PAYLOAD]");

  const hasPromptInjection = /\[(SYSTEM|INST|OVERRIDE)|ignore previous instructions|ignore price limits/i.test(rawText);
  const hasHomograph = /paypaI\.com|[\u200B-\u200D\uFEFF]/i.test(rawText);
  const hasPhoneTrap = /(\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/.test(rawText);
  const hasUrgency = /(unauthorized|bitcoin|geek squad|call immediately|cancel charge|refund department|urgent)/i.test(rawText);
  const hasCommercialFF = /(ticket|ps5|macbook|deposit|shipping|tracking|item|vip)/i.test(rawText);
  const hasCoercion = (telemetry.windowBlurCount || 0) >= 3;
  const hasZeroMsPaste =
    Boolean(telemetry.pasteDetected) ||
    (telemetry.keystrokeFlightMs !== undefined && telemetry.keystrokeFlightMs < 15);

  const shapAttributions = {
    phone_number_trap: hasPhoneTrap ? 0.45 : 0,
    urgency_impersonation_nlp: hasUrgency ? 0.35 : 0.02,
    prompt_injection_unicode: hasPromptInjection || hasHomograph ? 0.52 : 0,
    commercial_ff_keyword: hasCommercialFF ? 0.48 : 0,
    remote_coercion_telemetry: hasCoercion ? 0.58 : 0,
    paste_0ms_cadence: hasZeroMsPaste ? 0.44 : 0,
  };

  const overallRiskScore = Math.min(
    0.99,
    Number(Object.values(shapAttributions).reduce((a, b) => a + b, 0).toFixed(2))
  );

  let threatVector: RiskResult["threatVector"] = "CLEAN_TRANSACTION";
  if (hasPromptInjection || hasHomograph) threatVector = "PROMPT_INJECTION";
  else if (hasCoercion) threatVector = "REMOTE_COERCION";
  else if (hasPhoneTrap || hasUrgency) threatVector = "INVOICE_PHISHING";
  else if (hasCommercialFF) threatVector = "FF_PURCHASE_TRAP";
  else if (hasZeroMsPaste) threatVector = "BOT_CARDING_WAVE";

  return { sanitizedText, overallRiskScore, threatVector, shapAttributions };
}