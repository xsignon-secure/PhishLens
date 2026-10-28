# PhishLens MCP server

PhishLens is a [Model Context Protocol](https://modelcontextprotocol.io)
server, so Claude and other AI assistants can check and explain your domains'
email security in a conversation: "scan acme.com and tell me what to fix",
"which of my clients' domains got worse this month?", "is it safe to move
example.com to p=reject?".

The endpoint is `<APP_URL>/mcp` (streamable HTTP transport, JSON responses).
It answers as the team that owns the API key, and sees only that team's data.

## Connect

1. On the dashboard, create an API key (owners only). It starts with `plk_`.
2. Add the server to your client.

Claude Code:

```bash
claude mcp add --transport http phishlens https://YOUR-PHISHLENS/mcp \
  --header "Authorization: Bearer plk_..."
```

Any client that takes a JSON config:

```json
{
  "mcpServers": {
    "phishlens": {
      "type": "http",
      "url": "https://YOUR-PHISHLENS/mcp",
      "headers": {"Authorization": "Bearer plk_..."}
    }
  }
}
```

`X-API-Key: plk_...` works too. A browser session cookie is not accepted on
`/mcp`, so a web page can't use a signed-in user's session against it.

## Tools

| Tool | What it does |
| --- | --- |
| `scan_domain` | Scans a domain now and saves it to the team's history. Returns the score, grade, every failing check with its fix, and the passing checks. 60 per hour per team. |
| `get_latest_report` | The team's latest report for a domain, without rescanning. |
| `list_monitors` | Monitored domains with client label, last score, alert level and last check. |
| `list_alerts` | Recent alerts (`limit`, up to 100). |
| `dmarc_summary` | DMARC aggregate data for a domain over `days` (default 30): senders, pass rates, fixes, and whether quarantine or reject is safe. |
| `dns_changes` | Email-security DNS record changes seen for a monitored domain. |

Each result comes back as text (JSON) and as `structuredContent`.

## Limits

600 requests per hour per team, plus the scan limit above. The server
doesn't push notifications, so `GET /mcp` returns 405.

## Test it by hand

```bash
curl -s https://YOUR-PHISHLENS/mcp -H "Authorization: Bearer plk_..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_monitors","arguments":{}}}'
```
