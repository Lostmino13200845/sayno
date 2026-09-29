// Official domains of Canadian banks and payment services.
// A card form on one of these is expected; anywhere else it gets scrutiny.
const SS_BANKS = {
  rbc:          { name: "RBC Royal Bank",     domains: ["rbc.com", "rbcroyalbank.com"] },
  td:           { name: "TD Canada Trust",    domains: ["td.com", "tdcanadatrust.com"] },
  bmo:          { name: "BMO",                domains: ["bmo.com"] },
  scotiabank:   { name: "Scotiabank",         domains: ["scotiabank.com"] },
  cibc:         { name: "CIBC",               domains: ["cibc.com"] },
  national:     { name: "National Bank",      domains: ["nbc.ca"] },
  desjardins:   { name: "Desjardins",         domains: ["desjardins.com"] },
  tangerine:    { name: "Tangerine",          domains: ["tangerine.ca"] },
  simplii:      { name: "Simplii Financial",  domains: ["simplii.com"] },
  eq:           { name: "EQ Bank",            domains: ["eqbank.ca"] },
  vancity:      { name: "Vancity",            domains: ["vancity.com"] },
  coastcapital: { name: "Coast Capital",      domains: ["coastcapitalsavings.com"] },
  wealthsimple: { name: "Wealthsimple",       domains: ["wealthsimple.com"] },
  koho:         { name: "KOHO",               domains: ["koho.ca"] },
};

// Well-known payment pages where typing a card is normal.
const SS_PAYMENT_PROCESSORS = ["stripe.com", "paypal.com", "squareup.com", "shopify.com", "moneris.com",
  "checkout.com", "adyen.com", "braintreegateway.com", "amazon.ca", "amazon.com", "apple.com", "google.com"];

// Words that show a page is pretending to be (or talking about) a bank.
const SS_BANK_WORDS = /\b(bank|banking|royal bank|rbc|td canada|bmo|scotiabank|cibc|desjardins|tangerine|simplii|vancity|interac|e-?transfer|visa|mastercard|debit card|credit card|account holder)\b/i;
const SS_PRESSURE_WORDS = /\b(suspended|locked|frozen|verify your (card|account|identity)|confirm your (card|account|identity)|unusual (activity|sign.?in)|unauthori[sz]ed|security (alert|check)|update your (card|billing)|reactivate|avoid (suspension|closure)|pending (deposit|e-?transfer)|within \d+ hours)\b/i;

function ssRegistered(host) {
  const p = host.toLowerCase().split(".");
  return p.length >= 3 && ["co.uk", "com.au", "gc.ca"].includes(p.slice(-2).join(".")) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}
function ssHostMatches(host, domains) {
  host = host.toLowerCase();
  return domains.some(d => host === d || host.endsWith("." + d));
}
