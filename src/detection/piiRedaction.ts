export interface RedactionResult {
  redactedPayload: string;
  redactedFields: string[];
  originalFlagged: boolean;
  dataTypesDetected: string[];
}

export interface PiiPatternConfig {
  email?: boolean;
  phone?: boolean;
  creditCard?: boolean;
  ssn?: boolean;
  pesel?: boolean;
}

const DEFAULT_PII_PATTERNS: PiiPatternConfig = {
  email: true,
  phone: true,
  creditCard: true,
  ssn: true,
  pesel: true,
};

const EMAIL_PATTERN = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g;
const PHONE_PATTERN = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;
const CREDIT_CARD_PATTERN = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/g;
const PESEL_PATTERN = /\b\d{11}\b/g;

function luhnCheck(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  
  let sum = 0;
  let isEven = false;
  
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);
    
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isEven = !isEven;
  }
  
  return sum % 10 === 0;
}

function validatePesel(pesel: string): boolean {
  if (!/^\d{11}$/.test(pesel)) return false;
  
  const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  let sum = 0;
  
  for (let i = 0; i < 10; i++) {
    sum += parseInt(pesel[i], 10) * weights[i];
  }
  
  const checkDigit = (10 - (sum % 10)) % 10;
  return checkDigit === parseInt(pesel[10], 10);
}

export function redactPii(
  payload: string,
  patterns: PiiPatternConfig = DEFAULT_PII_PATTERNS
): RedactionResult {
  const redactedFields: string[] = [];
  const dataTypesDetected: string[] = [];
  let redactedPayload = payload;
  let originalFlagged = false;

  if (patterns.email !== false) {
    const emailMatches = payload.match(EMAIL_PATTERN);
    if (emailMatches && emailMatches.length > 0) {
      originalFlagged = true;
      dataTypesDetected.push('email');
      redactedFields.push('email');
      redactedPayload = redactedPayload.replace(EMAIL_PATTERN, '[REDACTED_EMAIL]');
    }
  }

  if (patterns.creditCard !== false) {
    const creditCardMatches = Array.from(redactedPayload.matchAll(CREDIT_CARD_PATTERN));
    for (const match of creditCardMatches) {
      if (luhnCheck(match[0])) {
        originalFlagged = true;
        if (!dataTypesDetected.includes('credit_card')) {
          dataTypesDetected.push('credit_card');
          redactedFields.push('credit_card');
        }
        redactedPayload = redactedPayload.replace(match[0], '[REDACTED_CREDIT_CARD]');
      }
    }
  }

  if (patterns.ssn !== false) {
    const ssnMatches = redactedPayload.match(SSN_PATTERN);
    if (ssnMatches && ssnMatches.length > 0) {
      originalFlagged = true;
      dataTypesDetected.push('ssn');
      redactedFields.push('ssn');
      redactedPayload = redactedPayload.replace(SSN_PATTERN, '[REDACTED_SSN]');
    }
  }

  if (patterns.pesel !== false) {
    const peselMatches = Array.from(redactedPayload.matchAll(PESEL_PATTERN));
    for (const match of peselMatches) {
      if (validatePesel(match[0])) {
        originalFlagged = true;
        if (!dataTypesDetected.includes('pesel')) {
          dataTypesDetected.push('pesel');
          redactedFields.push('pesel');
        }
        redactedPayload = redactedPayload.replace(match[0], '[REDACTED_PESEL]');
      }
    }
  }

  if (patterns.phone !== false) {
    const phoneMatches = redactedPayload.match(PHONE_PATTERN);
    if (phoneMatches && phoneMatches.length > 0) {
      originalFlagged = true;
      if (!dataTypesDetected.includes('phone')) {
        dataTypesDetected.push('phone');
        redactedFields.push('phone');
      }
      redactedPayload = redactedPayload.replace(PHONE_PATTERN, '[REDACTED_PHONE]');
    }
  }

  return {
    redactedPayload,
    redactedFields,
    originalFlagged,
    dataTypesDetected,
  };
}

export function redactJsonPayload(
  body: any,
  patterns: PiiPatternConfig = DEFAULT_PII_PATTERNS
): { redactedBody: any; result: RedactionResult } {
  if (!body) {
    return {
      redactedBody: body,
      result: {
        redactedPayload: '',
        redactedFields: [],
        originalFlagged: false,
        dataTypesDetected: [],
      },
    };
  }

  let jsonString: string;
  try {
    jsonString = typeof body === 'string' ? body : JSON.stringify(body);
  } catch {
    return {
      redactedBody: body,
      result: {
        redactedPayload: '',
        redactedFields: [],
        originalFlagged: false,
        dataTypesDetected: [],
      },
    };
  }

  const result = redactPii(jsonString, patterns);

  let redactedBody: any;
  try {
    redactedBody = JSON.parse(result.redactedPayload);
  } catch {
    redactedBody = result.redactedPayload;
  }

  return { redactedBody, result };
}
