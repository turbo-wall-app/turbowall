/**
 * WAF Rules Definition
 * Format:
 * - id: String identifier for the rule
 * - action: "block" | "allow" | "log"
 * - expression: see config.json for examples
 * * Supported Operators: ==, !=, contains
 * Supported Logic: and, or, (...)
 * Supported Fields: ip.src, http.request.uri.path, http.request.method, http.user_agent, http.host
 */
import WAF_RULES from "../config.json";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ==========================================
    // PHASE 1: REQUEST EVALUATION
    // ==========================================
    const reqBodyText = await safelyReadBody(request);

    const reqContext = {
      "ip.src": request.headers.get("cf-connecting-ip") || "127.0.0.1",
      "http.request.uri.path": url.pathname,
      "http.request.method": request.method,
      "http.user_agent": request.headers.get("user-agent") || "",
      "http.host": url.hostname,
      "http.request.body": reqBodyText,
    };

    const requestWafResult = runWafEngine(WAF_RULES, "request", reqContext);
    if (requestWafResult.blocked) {
      return requestWafResult.response;
    }

    // ==========================================
    // FETCH ORIGIN
    // ==========================================
    let originResponse;
    try {
      // If a rule had 'allow', it bypassed remaining rules but still reaches here
      originResponse = await fetch(request);
    } catch (e) {
      return new Response("Origin Error", { status: 502 });
    }

    // ==========================================
    // PHASE 2: RESPONSE EVALUATION
    // ==========================================
    const resBodyText = await safelyReadBody(originResponse);

    // Merge contexts so response rules can still evaluate request data if needed
    const resContext = {
      ...reqContext,
      "http.response.body": resBodyText,
      "http.response.code": String(originResponse.status),
    };

    const responseWafResult = runWafEngine(WAF_RULES, "response", resContext);
    if (responseWafResult.blocked) {
      return responseWafResult.response;
    }

    // If neither phase blocked, return the original response to the user
    return originResponse;
  },
};

/**
 * --- WAF RUNNER ---
 * Executes the rules for a specific phase
 */
function runWafEngine(rules, currentPhase, context) {
  for (const rule of rules) {
    // Skip rules that don't belong to the current execution phase
    if (rule.phase !== currentPhase) continue;

    if (evaluateExpression(rule.expression, context)) {
      switch (rule.action) {
        case "block":
          console.log(
            `[WAF BLOCK - ${currentPhase.toUpperCase()}] Rule: ${rule.id}`,
          );
          return {
            blocked: true,
            response: new Response(
              `403 Forbidden - Blocked by WAF at ${currentPhase} phase`,
              {
                status: 403,
                headers: { "Content-Type": "text/plain" },
              },
            ),
          };

        case "allow":
          console.log(
            `[WAF ALLOW - ${currentPhase.toUpperCase()}] Rule: ${rule.id}`,
          );
          return { blocked: false }; // Instantly break out and allow

        case "log":
          console.log(
            `[WAF LOG - ${currentPhase.toUpperCase()}] Rule: ${rule.id}`,
          );
          continue;
      }
    }
  }
  return { blocked: false };
}

/**
 * --- SAFE BODY READER ---
 * Safely clones and reads the HTTP body without crashing the Worker
 */
async function safelyReadBody(requestOrResponse) {
  // 1. Clone the stream so we don't consume the original
  const cloned = requestOrResponse.clone();

  try {
    const reader = cloned.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let text = "";
    let totalBytes = 0;
    const maxBytes = 128 * 1024; // 128KB limit

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalBytes += value.length;
      if (totalBytes > maxBytes) {
        // Only decode up to the remaining allowed bytes
        const overage = totalBytes - maxBytes;
        const allowedChunk = value.slice(0, value.length - overage);
        text += decoder.decode(allowedChunk, { stream: true });
        
        // Cancel the reader since we've hit our limit.
        // This is crucial to prevent downloading the rest of a huge file into memory.
        await reader.cancel("Reached WAF inspection limit");
        break;
      }

      text += decoder.decode(value, { stream: true });
    }
    
    // Flush the decoder
    text += decoder.decode();
    return text;
  } catch (e) {
    console.error("Failed to read body securely", e);
    return "";
  }
}

/**
 * --- EXPRESSION ENGINE (AST + Evaluator) ---
 */

function evaluateExpression(expr, ctx) {
  const tokens = tokenize(expr);
  if (!tokens.length) return false;
  const ast = parseTokens(tokens);
  return evaluateAST(ast, ctx);
}

function tokenize(expr) {
  const tokens = [];
  const regex =
    /\s*(?:(\()|(\))|(and|or|==|!=|contains|matches)|"([^"]*)"|'([^']*)'|([a-zA-Z0-9_.-]+))\s*/gi;
  let match;

  while ((match = regex.exec(expr)) !== null) {
    if (match[1]) tokens.push({ type: "LPAREN", val: "(" });
    else if (match[2]) tokens.push({ type: "RPAREN", val: ")" });
    else if (match[3]) tokens.push({ type: "OP", val: match[3].toLowerCase() });
    else if (match[4] !== undefined)
      tokens.push({ type: "STRING", val: match[4] });
    else if (match[5] !== undefined)
      tokens.push({ type: "STRING", val: match[5] });
    else if (match[6]) tokens.push({ type: "IDENT", val: match[6] });
  }
  return tokens;
}

function parseTokens(tokens) {
  let pos = 0;

  function parseExpr() {
    let node = parseTerm();
    while (pos < tokens.length && tokens[pos].val === "or") {
      pos++;
      node = { type: "OR", left: node, right: parseTerm() };
    }
    return node;
  }

  function parseTerm() {
    let node = parseFactor();
    while (pos < tokens.length && tokens[pos].val === "and") {
      pos++;
      node = { type: "AND", left: node, right: parseFactor() };
    }
    return node;
  }

  function parseFactor() {
    if (pos >= tokens.length) return null;
    if (tokens[pos].type === "LPAREN") {
      pos++;
      let node = parseExpr();
      if (pos < tokens.length && tokens[pos].type === "RPAREN") pos++;
      return node;
    }

    let field = tokens[pos++];
    let op = tokens[pos++];
    let val = tokens[pos++];

    if (!field || !op || !val) return { type: "ERROR" };
    return { type: "COND", field: field.val, op: op.val, value: val.val };
  }
  return parseExpr();
}

function wildcardMatch(str, pattern) {
  const escapeRegex = (s) => s.replace(/([.+?^=!:${}()|\[\]\/\\])/g, "\\$1");
  const regexStr = "^" + pattern.split("*").map(escapeRegex).join(".*") + "$";
  return new RegExp(regexStr, "i").test(str);
}

function evaluateAST(node, ctx) {
  if (!node || node.type === "ERROR") return false;
  if (node.type === "OR")
    return evaluateAST(node.left, ctx) || evaluateAST(node.right, ctx);
  if (node.type === "AND")
    return evaluateAST(node.left, ctx) && evaluateAST(node.right, ctx);

  if (node.type === "COND") {
    let rawFieldVal = String(
      ctx[node.field] !== undefined ? ctx[node.field] : "",
    );
    let lowerFieldVal = rawFieldVal.toLowerCase();

    let targetVal = String(node.value);
    let lowerTargetVal = targetVal.toLowerCase();

    switch (node.op) {
      case "==":
        if (targetVal.includes("*"))
          return wildcardMatch(lowerFieldVal, lowerTargetVal);
        return lowerFieldVal === lowerTargetVal;
      case "!=":
        if (targetVal.includes("*"))
          return !wildcardMatch(lowerFieldVal, lowerTargetVal);
        return lowerFieldVal !== lowerTargetVal;
      case "contains":
        return lowerFieldVal.includes(lowerTargetVal);
      case "matches":
        try {
          let isCaseInsensitive = targetVal.startsWith("(?i)");
          let cleanRegexStr = isCaseInsensitive
            ? targetVal.substring(4)
            : targetVal;
          let flags = isCaseInsensitive ? "i" : "";
          let regexPattern = new RegExp(cleanRegexStr, flags);
          return regexPattern.test(rawFieldVal);
        } catch (e) {
          console.error(`[WAF ERROR] Invalid Regex: ${targetVal}`);
          return false;
        }
      default:
        return false;
    }
  }
  return false;
}
