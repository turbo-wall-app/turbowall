/**
 * WAF Rules Definition
 * Format:
 * - id: String identifier for the rule
 * - action: "block" | "allow" | "log"
 * - expression: see config.json for examples
 * * Supported Operators: ==, !=, contains
 * Supported Logic: and, or, (...)
 * Supported Fields: ip.src, http.request.uri.path, http.request.method, http.user_agent, http.host
 * * NEW: Wildcards (*) are now supported for == and != operators.
 */
import WAF_RULES from "../config.json";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Map Cloudflare standard fields to the request context
    const reqContext = {
      "ip.src": request.headers.get("cf-connecting-ip") || "127.0.0.1",
      "http.request.uri.path": url.pathname,
      "http.request.method": request.method,
      "http.user_agent": request.headers.get("user-agent") || "",
      "http.host": url.hostname,
    };

    // 2. Evaluate WAF Rules
    for (const rule of WAF_RULES) {
      if (evaluateExpression(rule.expression, reqContext)) {
        switch (rule.action) {
          case "block":
            console.log(
              `[WAF BLOCK] Rule ID: ${rule.id} | IP: ${reqContext["ip.src"]} | Path: ${reqContext["http.request.uri.path"]}`,
            );
            return new Response("403 Forbidden - Request blocked by WAF", {
              status: 403,
              headers: { "Content-Type": "text/plain" },
            });

          case "allow":
            console.log(
              `[WAF ALLOW] Rule ID: ${rule.id} | IP: ${reqContext["ip.src"]}`,
            );
            break;

          case "log":
            console.log(
              `[WAF LOG] Rule ID: ${rule.id} | IP: ${reqContext["ip.src"]} | Path: ${reqContext["http.request.uri.path"]}`,
            );
            continue;
        }

        if (rule.action === "allow") {
          break;
        }
      }
    }

    // 3. Fetch Origin
    try {
      return await fetch(request);
    } catch (e) {
      return new Response("Origin Error", { status: 502 });
    }
  },
};

/**
 * --- EXPRESSION ENGINE ---
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
    /\s*(?:(\()|(\))|(and|or|==|!=|contains)|"([^"]*)"|'([^']*)'|([a-zA-Z0-9_.-]+))\s*/gi;
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

/**
 * Helper to safely convert wildcard strings (e.g., 192.168.*) into Regular Expressions
 */
function wildcardMatch(str, pattern) {
  // Escape all standard regex characters except the asterisk
  const escapeRegex = (s) => s.replace(/([.+?^=!:${}()|\[\]\/\\])/g, "\\$1");

  // Split by asterisk, escape the text chunks, then join with '.*'
  const regexStr = "^" + pattern.split("*").map(escapeRegex).join(".*") + "$";

  return new RegExp(regexStr, "i").test(str);
}

function evaluateAST(node, ctx) {
  if (!node || node.type === "ERROR") return false;

  if (node.type === "OR") {
    return evaluateAST(node.left, ctx) || evaluateAST(node.right, ctx);
  }

  if (node.type === "AND") {
    return evaluateAST(node.left, ctx) && evaluateAST(node.right, ctx);
  }

  if (node.type === "COND") {
    let fieldVal = String(
      ctx[node.field] !== undefined ? ctx[node.field] : "",
    ).toLowerCase();
    let targetVal = String(node.value).toLowerCase();

    switch (node.op) {
      case "==":
        if (targetVal.includes("*")) return wildcardMatch(fieldVal, targetVal);
        return fieldVal === targetVal;

      case "!=":
        if (targetVal.includes("*")) return !wildcardMatch(fieldVal, targetVal);
        return fieldVal !== targetVal;

      case "contains":
        return fieldVal.includes(targetVal);

      default:
        return false;
    }
  }

  return false;
}
