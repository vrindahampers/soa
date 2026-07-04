#!/usr/bin/env node

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function ensureEnvExists() {
    const envPath = path.join(__dirname, '..', '.env');
    const examplePath = path.join(__dirname, '..', '.env.example');

    if (!fs.existsSync(envPath) && fs.existsSync(examplePath)) {
        fs.copyFileSync(examplePath, envPath);
        console.log('Created .env from .env.example.');
    }
}

ensureEnvExists();
require('dotenv').config();

const port = String(process.env.PORT || 30000);
const visibility = process.env.CODESPACE_PORT_VISIBILITY || 'private';
const codespaceName = process.env.CODESPACE_NAME;
const forwardingDomain = process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN;
const isCodespaces = process.env.CODESPACES === 'true' && codespaceName && forwardingDomain;

function hasCommand(command) {
    const result = spawnSync(command, ['--version'], { stdio: 'ignore' });
    return result.status === 0;
}

function printAccessInfo() {
    console.log('');
    console.log(`Local URL: http://localhost:${port}`);
    console.log('VS Code Dev Tunnel: open the Ports panel, forward this port, then copy the Forwarded Address.');
    console.log('To share with a friend, right-click the port in VS Code and set Port Visibility to Public.');

    if (isCodespaces) {
        const tunnelUrl = `https://${codespaceName}-${port}.${forwardingDomain}`;
        console.log(`GitHub forwarded URL: ${tunnelUrl}`);
        console.log(`Port visibility: ${visibility}`);
    } else {
        console.log('GitHub forwarded URL: available automatically when this runs in Codespaces.');
    }

    console.log('');
}

function setCodespacesVisibility() {
    if (!isCodespaces || !hasCommand('gh')) return;

    const args = [
        'codespace',
        'ports',
        'visibility',
        `${port}:${visibility}`,
        '-c',
        codespaceName
    ];
    const result = spawnSync('gh', args, { encoding: 'utf8' });

    if (result.status === 0) {
        console.log(`Set GitHub Codespaces port ${port} visibility to ${visibility}.`);
    } else {
        const message = (result.stderr || result.stdout || '').trim();
        console.warn(`Could not set Codespaces port visibility automatically.${message ? ` ${message}` : ''}`);
    }
}

setCodespacesVisibility();
printAccessInfo();

const server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    stdio: 'inherit',
    env: process.env
});

function stopServer(signal) {
    if (!server.killed) {
        server.kill(signal);
    }
}

process.on('SIGINT', () => stopServer('SIGINT'));
process.on('SIGTERM', () => stopServer('SIGTERM'));

server.on('exit', (code, signal) => {
    if (signal) {
        process.kill(process.pid, signal);
        return;
    }

    process.exit(code || 0);
});
