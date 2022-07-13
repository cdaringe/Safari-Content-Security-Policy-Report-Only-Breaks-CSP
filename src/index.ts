import fastify from "fastify";
import fs from "fs";
import path from "path";

// const HOSTNAME = "local.dev";
const PORT = 8080;
const REPORT_PATHNAME = "/csp-violation-report";

/**
 * @info flip this switch to true observe CSP failures.
 * this turns on the Content-Security-Policy-Report-Only header
 */
const CSP_REPORT_VALUE = false
  ? `script-src 'self' 'strict-dynamic' 'nonce-abc123'; report-uri  ${REPORT_PATHNAME}`
  : "";

const CSP_SCRIPT_MODE_UNSAFE_WITHOUT_NONCE = `script-src * 'unsafe-eval' 'unsafe-inline'`;
const CSP_VALUE = `${CSP_SCRIPT_MODE_UNSAFE_WITHOUT_NONCE}; report-uri  ${REPORT_PATHNAME}`;

async function go() {
  const server = fastify();

  server.addContentTypeParser(
    "application/csp-report",
    { parseAs: "string" },
    server.getDefaultJsonParser("ignore", "ignore")
  );

  server.get("/", async (_request, reply) => {
    reply.header("Content-Security-Policy", CSP_VALUE).type("text/html");
    if (CSP_REPORT_VALUE) {
      reply.header("Content-Security-Policy-Report-Only", CSP_REPORT_VALUE);
    }
    reply.send(fs.readFileSync(path.join(__dirname, "index.html")));
  });

  server.get("/self.js", async (_request, reply) => {
    reply
      .type("application/javascript")
      .send(`console.log("case: 'self' script, foo.js")`);
  });

  server.post(REPORT_PATHNAME, async (req, reply) => {
    const report = (req.body as CspReportPayload)["csp-report"];
    console.log(
      `[csp violation report (${report["violated-directive"]})]: ${report["blocked-uri"]}`
    );
    reply.status(200).send({ ok: true });
  });
  server.listen(PORT, (err, address) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`Server listening at ${address}`);
  });
}

interface CspReportPayload {
  "csp-report": {
    "document-uri": string;
    referrer: string;
    "violated-directive": string;
    "effective-directive": string;
    "original-policy": string;
    disposition: string;
    "blocked-uri": string;
    "status-code": number;
    "script-sample": string;
  };
}

go();
