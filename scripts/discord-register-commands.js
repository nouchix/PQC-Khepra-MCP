#!/usr/bin/env node
/**
 * Discord Slash Command Registration Script
 * Run once: node scripts/discord-register-commands.js
 *
 * Requires: DISCORD_BOT_TOKEN and DISCORD_APPLICATION_ID env vars
 * Or pass as args: node scripts/discord-register-commands.js <APP_ID> <BOT_TOKEN>
 */

const APP_ID = process.argv[2] || process.env.DISCORD_APPLICATION_ID || "1477741085219619020";
const TOKEN = process.argv[3] || process.env.DISCORD_BOT_TOKEN;

if (!TOKEN) {
    console.error("❌ Missing DISCORD_BOT_TOKEN. Pass as 2nd arg or set env var.");
    process.exit(1);
}

const commands = [
    // --- Security Operations ---
    {
        name: "scan",
        description: "🔍 Scan an IP address or domain for threat intelligence",
        options: [
            {
                name: "target",
                description: "IP address or domain to scan (e.g. 192.168.1.1 or example.com)",
                type: 3,
                required: true,
            },
        ],
    },
    {
        name: "alerts",
        description: "📬 Show the most recent security alerts",
        options: [
            {
                name: "severity",
                description: "Filter by severity level",
                type: 3,
                required: false,
                choices: [
                    { name: "CRITICAL", value: "CRITICAL" },
                    { name: "HIGH", value: "HIGH" },
                    { name: "MEDIUM", value: "MEDIUM" },
                    { name: "LOW", value: "LOW" },
                ],
            },
            {
                name: "count",
                description: "Number of alerts to show (default: 10, max: 25)",
                type: 4, // INTEGER
                required: false,
                min_value: 1,
                max_value: 25,
            },
        ],
    },
    {
        name: "firewall",
        description: "🔥 View or manage Polymorphic API firewall rules",
        options: [
            {
                name: "action",
                description: "Action to perform",
                type: 3,
                required: true,
                choices: [
                    { name: "List active rules", value: "list" },
                    { name: "Block an IP", value: "block" },
                    { name: "Unblock an IP", value: "unblock" },
                    { name: "Show blocked IPs", value: "blocked" },
                ],
            },
            {
                name: "ip",
                description: "IP address (required for block/unblock)",
                type: 3,
                required: false,
            },
        ],
    },
    {
        name: "threat-feed",
        description: "🌐 View latest threat intelligence feed entries",
        options: [
            {
                name: "source",
                description: "Feed source to query",
                type: 3,
                required: false,
                choices: [
                    { name: "CISA KEV", value: "cisa" },
                    { name: "AlienVault OTX", value: "otx" },
                    { name: "AbuseIPDB", value: "abuseipdb" },
                    { name: "All Sources", value: "all" },
                ],
            },
        ],
    },
    // --- Compliance & STIG ---
    {
        name: "compliance",
        description: "📋 Check current CMMC compliance status and score",
    },
    {
        name: "stig",
        description: "📜 View STIG findings and benchmark status",
        options: [
            {
                name: "action",
                description: "What to check",
                type: 3,
                required: true,
                choices: [
                    { name: "Summary", value: "summary" },
                    { name: "Open findings", value: "open" },
                    { name: "Recent changes", value: "changes" },
                ],
            },
        ],
    },
    // --- Infrastructure ---
    {
        name: "status",
        description: "✅ Check health status of all Khepra services",
    },
    {
        name: "deploy",
        description: "🚀 View deployment status or trigger a deploy",
        options: [
            {
                name: "action",
                description: "Deployment action",
                type: 3,
                required: true,
                choices: [
                    { name: "Show last deploy", value: "last" },
                    { name: "Show all services", value: "services" },
                ],
            },
        ],
    },
    {
        name: "audit",
        description: "📝 View DAG audit log entries",
        options: [
            {
                name: "count",
                description: "Number of entries to show (default: 10)",
                type: 4,
                required: false,
                min_value: 1,
                max_value: 50,
            },
        ],
    },
    // --- Users & Licensing ---
    {
        name: "users",
        description: "👥 View registered users and their roles",
        options: [
            {
                name: "action",
                description: "User action",
                type: 3,
                required: true,
                choices: [
                    { name: "List recent users", value: "list" },
                    { name: "Count by role", value: "stats" },
                    { name: "Search by email", value: "search" },
                ],
            },
            {
                name: "query",
                description: "Search query (for search action)",
                type: 3,
                required: false,
            },
        ],
    },
    {
        name: "license",
        description: "🔑 Look up a license key status",
        options: [
            {
                name: "key",
                description: "The license key to check",
                type: 3,
                required: true,
            },
        ],
    },
    // --- AI & Utility ---
    {
        name: "papyrus",
        description: "🤖 Chat with Papyrus AI assistant",
        options: [
            {
                name: "message",
                description: "Your message to Papyrus",
                type: 3,
                required: true,
            },
        ],
    },
    {
        name: "help",
        description: "❓ Show all available bot commands and their descriptions",
    },
];

async function registerCommands() {
    console.log(`🤖 Registering ${commands.length} slash commands for Khepra-Protocol-Crypto-PQC-Cyber...`);
    console.log(`   Application ID: ${APP_ID}`);

    const url = `https://discord.com/api/v10/applications/${APP_ID}/commands`;

    const response = await fetch(url, {
        method: "PUT",
        headers: {
            "Authorization": `Bot ${TOKEN}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(commands),
    });

    if (!response.ok) {
        const error = await response.text();
        console.error(`❌ Failed to register commands: ${response.status}`);
        console.error(error);
        process.exit(1);
    }

    const result = await response.json();
    console.log(`✅ Registered ${result.length} commands:`);
    result.forEach((cmd) => {
        console.log(`   /${cmd.name} — ${cmd.description}`);
    });
}

try {
    await registerCommands();
} catch (error) {
    console.error(error);
}
