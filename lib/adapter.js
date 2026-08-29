'use strict';

// File-basiertes Debug-Logging (sichtbar unabhaengig von ioBroker)
const _fs0 = require('node:fs');
const _DBG_PATH = '/tmp/fritzwireguard-debug.log';
const _dbg = (msg) => {
    try { _fs0.appendFileSync(_DBG_PATH,
        new Date().toISOString() + ' ' + msg + '\n'); } catch (_) {}
};
try {
    const st = _fs0.statSync(_DBG_PATH);
    if (st.size > 1024 * 1024) _fs0.writeFileSync(_DBG_PATH, '');
} catch (_) {}
_dbg('=== lib/adapter.js geladen ===');

const http        = require('node:http');
const net         = require('node:net');
const url         = require('node:url');
const fs          = require('node:fs');
const os          = require('node:os');
const path        = require('node:path');
const { exec }    = require('node:child_process');

// ─── TR-064 SOAP ─────────────────────────────────────────────────────────────

function soapRequest(host, port, service, action, body, user, pass) {
    return new Promise((resolve, reject) => {
        const xml =
            '<?xml version="1.0" encoding="utf-8"?>' +
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"' +
            ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
            '<s:Body>' + body + '</s:Body></s:Envelope>';

        const auth = 'Basic ' + Buffer.from(user + ':' + pass).toString('base64');
        const opts = {
            hostname: host, port: port || 49000, path: service, method: 'POST',
            headers: {
                'Content-Type':   'text/xml; charset=utf-8',
                'SOAPAction':     '"' + action + '"',
                'Content-Length': Buffer.byteLength(xml),
                'Authorization':  auth
            }
        };
        const req = http.request(opts, res => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end',  () => resolve(data));
        });
        req.on('error', reject);
        req.setTimeout(8000, () => { req.destroy(); reject(new Error('TR-064 Timeout')); });
        req.write(xml);
        req.end();
    });
}

function parseXml(xml, tag) {
    const m = xml.match(new RegExp('<' + tag + '>([\\s\\S]*?)<\\/' + tag + '>'));
    return m ? m[1].trim() : null;
}

// wg-quick erlaubt Interface-Namen max. 15 Zeichen (siehe /usr/bin/wg-quick)
const WG_IFACE = 'fritzwg';

// ─── WireGuard Config Sanitizer ───────────────────────────────────────────────
// Verhindert DNS-Manipulation und Full-Tunnel durch wg-quick

function sanitizeWgConfig(raw, opts = {}) {
    const warnings = [];
    let cfg = raw;

    if (/^DNS\s*=/mi.test(cfg)) {
        cfg = cfg.replace(/^DNS\s*=.+\n?/gim, '');
        warnings.push('Removed DNS lines — prevents system-wide DNS changes by wg-quick.');
    }
    if (/0\.0\.0\.0\/0/.test(cfg)) {
        cfg = cfg.replace(/,\s*0\.0\.0\.0\/0/g, '').replace(/0\.0\.0\.0\/0\s*,?\s*/g, '');
        warnings.push('Removed 0.0.0.0/0 from AllowedIPs — full-tunnel would block local network access for other adapters.');
    }
    if (/::\/0/.test(cfg)) {
        cfg = cfg.replace(/,\s*::\/0/g, '').replace(/::\/0\s*,?\s*/g, '');
        warnings.push('Removed ::/0 from AllowedIPs (IPv6 full-tunnel).');
    }
    if (/^Address\s*=/im.test(cfg) && /\d+\.\d+\.\d+\.\d+\/24/.test(cfg)) {
        cfg = cfg.replace(/(\d+\.\d+\.\d+\.\d+)\/24/g, '$1/32');
        warnings.push('Changed Interface Address from /24 to /32 — prevents routing the whole subnet via WG.');
    }
    if (/^Address\s*=.*:/im.test(cfg)) {
        cfg = cfg.replace(/^(Address\s*=\s*[\d.]+\/\d+)[^\n]*/gim, '$1');
        warnings.push('Removed IPv6 address from Interface block (IPv4-only tunnel).');
    }
    if (/^AllowedIPs\s*=.*:/im.test(cfg)) {
        cfg = cfg.replace(/^AllowedIPs\s*=\s*([^\n]+)$/gim, (line, val) =>
            'AllowedIPs = ' + val.split(',').map(s => s.trim()).filter(s => s && !s.includes(':')).join(', '));
        warnings.push('Removed IPv6 entries from AllowedIPs.');
    }
    const tunnelHosts = (opts.tunnelHosts || []).filter(Boolean);
    if (tunnelHosts.length && /^AllowedIPs\s*=/mi.test(cfg)) {
        const hosts  = [...new Set(tunnelHosts)];
        const narrow = hosts.map(h => h + '/32').join(', ');
        const allowedMatch = cfg.match(/^AllowedIPs\s*=\s*(.+)$/im);
        // Breite AllowedIPs (/8-/24) bei gleichem Subnetz lokal/remote → lokales Netz unerreichbar
        if (allowedMatch && /\/(?:24|16|8)\b/.test(allowedMatch[1])) {
            cfg = cfg.replace(/^AllowedIPs\s*=.+\n?/gim, 'AllowedIPs = ' + narrow + '\n');
            warnings.push('Narrowed AllowedIPs to tunnel hosts (excluding local FritzBox): ' + hosts.join(', '));
        }
    }
    return { cfg, warnings };
}

// ─── WireGuard System-Calls ───────────────────────────────────────────────────

function execWg(cmd) {
    const normalized = cmd
        .replace(/^wg-quick\b/, '/usr/bin/wg-quick')
        .replace(/^wg show\b/, '/usr/bin/wg show')
        .replace(/^wg\b/, '/usr/bin/wg')
        .replace(/^ip\b/, '/usr/sbin/ip');
    // In this LXC/ioBroker setup (Node with setcap + sudo-rs), capturing wg/ip
    // stdout directly from child_process often yields an empty string (exit 0).
    // Piping through cat returns the real output reliably.
    const isQuery = /(^|\/)wg(\s|$)/.test(normalized) && /\bshow\b/.test(normalized)
        || /(^|\/)ip(\s|$)/.test(normalized);
    const shellCmd = isQuery
        ? (normalized + ' | /bin/cat')
        : ('sudo -n ' + normalized);
    return new Promise((resolve, reject) => {
        exec('/bin/bash -c ' + JSON.stringify(shellCmd) + ' 2>&1', (err, stdout) => {
            if (err) return reject(new Error((stdout || err.message || 'wg failed').trim()));
            resolve(stdout || '');
        });
    });
}

function parseWgBytes(raw) {
    if (!raw) return 0;
    const m = String(raw).trim().match(/^([\d.]+)\s*(B|KiB|MiB|GiB)$/i);
    if (!m) return parseInt(raw, 10) || 0;
    const n = parseFloat(m[1]);
    const u = m[2].toLowerCase();
    if (u === 'kib') return Math.round(n * 1024);
    if (u === 'mib') return Math.round(n * 1048576);
    if (u === 'gib') return Math.round(n * 1073741824);
    return Math.round(n);
}

function wgStatus(iface) {
    return new Promise(resolve => {
        execWg('/usr/bin/wg show ' + iface).then(stdout => {
            const peers = [];
            const blocks = /\n\n/.test(stdout)
                ? stdout.split(/\n\n/)
                : stdout.split(/\n(?=peer:)/);
            for (const block of blocks) {
                const b = block.trim();
                if (!b.startsWith('peer:')) continue;
                peers.push({
                    pubkey:    (b.match(/^peer: (.+)/m)  || [])[1] || '',
                    endpoint:  (b.match(/endpoint: (.+)/m) || [])[1] || '',
                    handshake: (b.match(/latest handshake: (.+)/m) || [])[1] || 'nie',
                    rx: parseWgBytes((b.match(/transfer: ([\d.]+\s*(?:B|KiB|MiB|GiB)) received/im) || [])[1]),
                    tx: parseWgBytes((b.match(/transfer: [^,\n]+,\s*([\d.]+\s*(?:B|KiB|MiB|GiB)) sent/im) || [])[1])
                });
            }
            const ifaceUp = /^interface:/m.test(stdout) || peers.length > 0;
            const connected = peers.some(p => p.handshake !== 'nie' || p.rx > 0);
            resolve({ ifaceUp, connected, peers });
        }).catch(() => resolve({ ifaceUp: false, connected: false, peers: [] }));
    });
}

async function wgEnsureDown(cfgPath) {
    await wgDown(cfgPath).catch(() => {});
    await execWg('ip link del ' + WG_IFACE).catch(() => {});
}

function wgUp(cfgPath) {
    return execWg('wg-quick up ' + cfgPath);
}

function wgDown(cfgPath) {
    return execWg('wg-quick down ' + cfgPath).then(out => out || '').catch(() => '');
}

// ─── TCP Tunnel Manager ───────────────────────────────────────────────────────
// \u00d6ffnet lokale Ports (Standard: 127.0.0.1) und leitet Verbindungen transparent
// durch den WireGuard-Tunnel weiter. Mit exposeLan zus\u00e4tzlich im LAN erreichbar.

function primaryLanIp() {
    const ifs = os.networkInterfaces();
    for (const list of Object.values(ifs)) {
        for (const i of list || []) {
            const fam = i.family;
            if ((fam === 'IPv4' || fam === 4) && !i.internal) return i.address;
        }
    }
    return null;
}

class TunnelManager {
    constructor(logFn) {
        this._log     = logFn;
        this._servers = new Map();  // id \u2192 { server, cfg }
        this._stats   = new Map();  // id \u2192 { active, total, rx, tx, error }
        this._lanIp   = primaryLanIp();
    }

    start(t) {
        const id = t.id || t.name;
        if (this._servers.has(id) || !t.enabled) return;

        const stats = { active: 0, total: 0, rxBytes: 0, txBytes: 0, error: null };
        this._stats.set(id, stats);

        const bindHost = t.exposeLan ? '0.0.0.0' : '127.0.0.1';

        const server = net.createServer(local => {
            stats.active++;
            stats.total++;
            const remote = net.connect(parseInt(t.remotePort), t.remoteHost, () => {
                this._log('INFO', 'TUNNEL',
                    t.name + ': ' + local.remoteAddress + ' \u2192 ' + t.remoteHost + ':' + t.remotePort);
            });

            local.pipe(remote);
            remote.pipe(local);
            local.on('data',  d => { stats.rxBytes += d.length; });
            remote.on('data', d => { stats.txBytes += d.length; });

            const end = () => {
                stats.active = Math.max(0, stats.active - 1);
                local.destroy();
                remote.destroy();
            };
            local.on('close',  end);
            remote.on('close', end);
            local.on('error',  e => { this._log('WARN', 'TUNNEL', t.name + ' local: '  + e.message); end(); });
            remote.on('error', e => { this._log('WARN', 'TUNNEL', t.name + ' remote: ' + e.message); end(); });
        });

        server.on('error', e => {
            stats.error = e.message;
            this._log('ERROR', 'TUNNEL', t.name + ': Port ' + t.localPort + ' Fehler: ' + e.message);
        });

        server.listen(parseInt(t.localPort), bindHost, () => {
            const shown = t.exposeLan
                ? (this._lanIp ? this._lanIp + ':' + t.localPort + ' (LAN)' : '0.0.0.0:' + t.localPort)
                : '127.0.0.1:' + t.localPort;
            this._log('INFO', 'TUNNEL',
                t.name + ': ' + shown + ' \u2192 ' + t.remoteHost + ':' + t.remotePort);
        });

        this._servers.set(id, { server, cfg: t });
    }

    startAll(tunnels) { for (const t of (tunnels || [])) this.start(t); }

    stop(id) {
        const e = this._servers.get(id);
        if (e) { e.server.close(); this._servers.delete(id); this._stats.delete(id); }
    }

    stopAll() { for (const id of [...this._servers.keys()]) this.stop(id); }

    statusAll(tunnelCfg) {
        const lanIp = this._lanIp || primaryLanIp();
        return (tunnelCfg || []).map(t => {
            const id    = t.id || t.name;
            const stats = this._stats.get(id) || {};
            const exposeLan = !!t.exposeLan;
            return {
                id, name: t.name,
                localPort: t.localPort, remoteHost: t.remoteHost, remotePort: t.remotePort,
                enabled:  t.enabled,
                exposeLan,
                bindHost: exposeLan ? '0.0.0.0' : '127.0.0.1',
                lanIp:    exposeLan ? lanIp : null,
                running:  this._servers.has(id),
                active:   stats.active  || 0,
                total:    stats.total   || 0,
                rxBytes:  stats.rxBytes || 0,
                txBytes:  stats.txBytes || 0,
                error:    stats.error   || null
            };
        });
    }
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

class FritzWireguardLogic {

    _cfgFromMessage(msg) {
        const m = msg || {};
        return {
            ...this.config,
            wgConfig:       m.wgConfig       !== undefined ? m.wgConfig       : this.config.wgConfig,
            fritzHost:      m.fritzHost      !== undefined ? m.fritzHost      : this.config.fritzHost,
            fritzPort:      m.fritzPort      !== undefined ? m.fritzPort      : this.config.fritzPort,
            fritzUser:      m.fritzUser      !== undefined ? m.fritzUser      : this.config.fritzUser,
            fritzPass:      m.fritzPass      !== undefined ? m.fritzPass      : this.config.fritzPass,
            webPort:        m.webPort        !== undefined ? m.webPort        : this.config.webPort,
            autoConnect:    m.autoConnect    !== undefined ? m.autoConnect    : this.config.autoConnect,
            tunnels:        m.tunnels        !== undefined ? m.tunnels        : this.config.tunnels
        };
    }

    _sanitizeOpts(cfg) {
        const tunnels = cfg.tunnels || this.config.tunnels || [];
        return {
            tunnelHosts: tunnels.filter(t => t && t.enabled && t.remoteHost).map(t => t.remoteHost)
        };
    }

    _writeTempConfigFrom(cfg) {
        const { cfg: sanitized, warnings } = sanitizeWgConfig(cfg.wgConfig || '', this._sanitizeOpts(cfg));
        for (const w of warnings) this._log('WARN', 'WG', w);
        const dir  = path.join(os.tmpdir(), 'fritzwireguard');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = path.join(dir, WG_IFACE + '.conf');
        fs.writeFileSync(file, sanitized, { mode: 0o600 });
        return file;
    }

    async _runConnectionChecks(cfg, tryConnect) {
        const lines = [];
        let wgOk = false;
        let tr064Ok = false;
        let tunnelCount = 0;

        if (!cfg.wgConfig || !cfg.wgConfig.trim()) {
            lines.push('<span style="color:#f44336">&#10008; WireGuard-Config fehlt</span>');
            return { wgOk, tr064Ok, tunnelCount, lines, level: 'fail' };
        }

        let wgState = await wgStatus(WG_IFACE);
        if (!wgState.connected && tryConnect) {
            try {
                const cfgPath = this._writeTempConfigFrom(cfg);
                if (wgState.ifaceUp) await wgEnsureDown(cfgPath);
                await wgUp(cfgPath);
                wgState = await wgStatus(WG_IFACE);
            } catch (e) {
                lines.push('<span style="color:#f44336">&#10008; WireGuard: ' + this._esc(e.message) + '</span>');
            }
        }

        if (wgState.connected) {
            wgOk = true;
            const hs = wgState.peers[0] ? wgState.peers[0].handshake : 'unbekannt';
            lines.push('<span style="color:#4caf50">&#10004; WireGuard verbunden</span> (Handshake: ' + this._esc(hs) + ')');
        } else if (wgState.ifaceUp) {
            lines.push('<span style="color:#ff9800">&#9888; WireGuard interface up, but no handshake</span> — Check endpoint/config.');
        } else {
            lines.push('<span style="color:#f44336">&#10008; WireGuard not connected</span> — Enable Auto-Connect? Check sudo/wg-quick.');
        }

        if (cfg.fritzUser && cfg.fritzPass) {
            try {
                const h = cfg.fritzHost || '192.168.178.1';
                const p = parseInt(cfg.fritzPort) || 49000;
                const r = await soapRequest(h, p,
                    '/tr064/upnp/control/deviceinfo',
                    'urn:dslforum-org:service:DeviceInfo:1#GetInfo',
                    '<u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1"/>',
                    cfg.fritzUser, cfg.fritzPass);
                const model = parseXml(r, 'NewModelName');
                if (model) {
                    tr064Ok = true;
                    lines.push('<span style="color:#4caf50">&#10004; TR-064 reachable</span> (' + this._esc(model) + ')');
                } else {
                    lines.push('<span style="color:#ff9800">&#9888; TR-064: response without model name</span> — with the same subnet (192.168.178.x) the <b>local</b> FritzBox often answers instead of the remote one (optional; Kostal tunnels are independent).');
                }
            } catch (e) {
                lines.push('<span style="color:#ff9800">&#9888; TR-064: ' + this._esc(e.message) + '</span> (optional for Kostal tunnels)');
            }
        } else {
            lines.push('<span style="color:#8899bb">&#9432; TR-064 not configured (optional)</span>');
        }

        const tunnels = (cfg.tunnels || []).filter(t => t && t.enabled);
        tunnelCount = tunnels.length;
        if (tunnelCount) {
            const running = this._tunnelMgr
                ? this._tunnelMgr.statusAll(cfg.tunnels).filter(t => t.enabled && t.running).length
                : 0;
            lines.push('<span style="color:' + (running ? '#4caf50' : '#ff9800') + '">' +
                (running ? '&#10004;' : '&#9888;') + ' Tunnels: ' + running + '/' + tunnelCount + ' aktiv</span>');
            for (const t of tunnels) {
                lines.push('&nbsp;&nbsp;&#8594; 127.0.0.1:' + t.localPort + ' &rarr; ' +
                    this._esc(t.remoteHost) + ':' + t.remotePort + ' (' + this._esc(t.name || '') + ')');
            }
        } else {
            lines.push('<span style="color:#ff9800">&#9888; Kein aktiver Port-Tunnel konfiguriert</span>');
        }

        if (!cfg.autoConnect) {
            lines.push('<span style="color:#ff9800">&#9888; Auto-Connect is disabled</span>');
        }

        let level = 'fail';
        if (wgOk && tunnelCount > 0) level = tr064Ok || !cfg.fritzUser ? 'ok' : 'partial';
        else if (wgOk) level = 'partial';

        return { wgOk, tr064Ok, tunnelCount, lines, level };
    }

    _esc(s) {
        return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    async onMessage(obj) {
        if (!obj || !obj.command) return false;

        if (!this.adapterReady) {
            // Kein sendTo() — blockiert States-DB-Init (Admin textSendTo waehrend Start)
            return true;
        }

        try {
            switch (obj.command) {
                case 'getConnectionStatus': {
                    const cfg = this._cfgFromMessage(obj.message);
                    const r = await this._runConnectionChecks(cfg, false);
                    if (obj.callback) {
                        this.sendTo(obj.from, obj.command, {
                            text: r.lines.join('<br>'),
                            style: { fontSize: '0.9rem', lineHeight: '1.6' }
                        }, obj.callback);
                    }
                    return true;
                }
                case 'testConnection': {
                    const cfg = this._cfgFromMessage(obj.message);
                    const r = await this._runConnectionChecks(cfg, true);
                    if (obj.callback) {
                        this.sendTo(obj.from, obj.command, {
                            result: r.level,
                            text: r.lines.join('\n'),
                            message: r.lines.map(l => l.replace(/<[^>]+>/g, '')).join(' ')
                        }, obj.callback);
                    }
                    await this._poll();
                    return true;
                }
                case 'openWebUI': {
                    const cfg = this._cfgFromMessage(obj.message);
                    const port = parseInt(cfg.webPort) || 8094;
                    let host = '127.0.0.1';
                    const origin = obj.message && (obj.message._originIp || obj.message._origin);
                    if (origin) {
                        try {
                            const u = new URL(origin.includes('://') ? origin : 'http://' + origin);
                            host = u.hostname;
                        } catch (_) {}
                    }
                    if (obj.callback) {
                        this.sendTo(obj.from, obj.command, {
                            openUrl: 'http://' + host + ':' + port + '/',
                            window: '_blank'
                        }, obj.callback);
                    }
                    return true;
                }
            }
        } catch (e) {
            if (obj.callback) {
                this.sendTo(obj.from, obj.command, { error: 'fail', message: e.message }, obj.callback);
            }
            return true;
        }
        return false;
    }

    // Logging
    _log(level, category, msg) {
        const e = { ts: Date.now(), level, category, msg };
        this._logBuffer.unshift(e);
        if (this._logBuffer.length > ((this.config && this.config.logBuffer) || 500)) this._logBuffer.pop();
        // this.log kann in fruehen Initialisierungsphasen noch undefined sein
        const l = this.log;
        if (!l) { console.log('[' + level + '][' + category + '] ' + msg); return; }
        // WICHTIG: debug-Level wird von ioBroker standardmaessig gefiltert!
        // SYSTEM + INFO -> info, WARN -> warn, ERROR -> error
        if      (level === 'ERROR')  l.error('[' + category + '] ' + msg);
        else if (level === 'WARN')   l.warn('[' + category + '] ' + msg);
        else if (level === 'SYSTEM') l.info('[' + category + '] ' + msg);
        else if (level === 'INFO')   l.info('[' + category + '] ' + msg);
        else                         l.debug('[' + category + '] ' + msg);
    }

    // States
    async _initStates() {
        // Parent-Channels zuerst anlegen (adapter-core v3 benoetigt das)
        for (const [chId, chName] of [
            ['info',      'Adapter info'],
            ['wireguard', 'WireGuard'],
            ['fritzbox',  'FritzBox'],
            ['devices',   'Network devices'],
        ]) {
            try {
                await this.extendObjectAsync(chId, {
                    type:   chId === 'devices' ? 'folder' : 'channel',
                    common: { name: chName },
                    native: {}
                });
            } catch (_e) { /* channel already exists or non-critical */ }
        }

        // States anlegen/aktualisieren
        // extendObjectAsync ist zuverlaessiger als setObjectNotExistsAsync in adapter-core v3
        for (const entry of [
            ['info.connection',          'boolean', false, 'Adapter connected',       'indicator.connected'],
            ['info.lastUpdate',          'string',  '',    'Last update',             'text'],
            ['wireguard.status',         'string',  '',    'WireGuard status',        'text'],
            ['wireguard.handshake',      'string',  '',    'Last handshake',          'text'],
            ['wireguard.rxBytes',        'number',  0,     'Received bytes',          'value', 'B'],
            ['wireguard.txBytes',        'number',  0,     'Sent bytes',              'value', 'B'],
            ['fritzbox.externalIP',      'string',  '',    'External IP',             'info.ip'],
            ['fritzbox.uptime',          'number',  0,     'Uptime',                  'value', 's'],
            ['fritzbox.connectionType',  'string',  '',    'Connection type',         'text'],
            ['fritzbox.modelName',       'string',  '',    'FritzBox model',          'text'],
            ['fritzbox.firmwareVersion', 'string',  '',    'Firmware version',        'text'],
        ]) {
            const [id, stateType, defVal, stName, role, unit] = entry;
            try {
                const common = {
                    name:  stName,
                    type:  stateType,
                    role:  role,
                    read:  true,
                    write: false,
                    def:   defVal
                };
                if (unit) common.unit = unit;
                await this.extendObjectAsync(id, {
                    type:   'state',
                    common,
                    native: {}
                });
            } catch (_e) { /* state already exists or non-critical */ }
        }
    }

    // WireGuard Config
    _writeTempConfig() {
        const { cfg, warnings } = sanitizeWgConfig(this.config.wgConfig || '', this._sanitizeOpts(this.config));
        for (const w of warnings) this._log('WARN', 'WG', w);
        const dir  = path.join(os.tmpdir(), 'fritzwireguard');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        const file = path.join(dir, WG_IFACE + '.conf');
        fs.writeFileSync(file, cfg, { mode: 0o600 });
        this._wgCfgPath = file;
        return file;
    }

    // WireGuard Connect / Disconnect
    async _connectWg() {
        try {
            this._log('INFO', 'WG', 'Starting WireGuard \u2026');
            const cfgPath = this._writeTempConfig();
            const existing = await wgStatus(WG_IFACE);
            if (existing.ifaceUp) {
                this._log('INFO', 'WG', 'Existing interface ' + WG_IFACE + ' will be reloaded \u2026');
                await wgEnsureDown(cfgPath);
            }
            await wgUp(cfgPath);
            const st = await wgStatus(WG_IFACE);
            if (st.connected) {
                this._log('INFO', 'WG', 'WireGuard connected.');
            } else {
                this._log('WARN', 'WG', 'Interface is up, but no handshake with peer yet.');
            }
            return st.connected;
        } catch (e) {
            this._log('ERROR', 'WG', 'wg-quick up: ' + e.message);
            return false;
        }
    }

    async _disconnectWg() {
        if (!this._wgCfgPath) return;
        try { await wgDown(this._wgCfgPath); this._log('INFO', 'WG', 'WireGuard disconnected.'); }
        catch (e) { this._log('WARN', 'WG', 'wg-quick down: ' + e.message); }
    }

    // FritzBox TR-064
    async _pollFritzBox() {
        const h = this.config.fritzHost || '192.168.178.1';
        const p = parseInt(this.config.fritzPort) || 49000;
        const u = this.config.fritzUser || '';
        const pw = this.config.fritzPass || '';

        const set = async (state, val) => {
            this._cache.fritzbox[state.split('.')[1]] = val;
            await this.setStateAsync('fritzbox.' + state.split('.')[1], { val, ack: true });
        };

        try {
            const r = await soapRequest(h, p,
                '/igdupnp/control/WANIPConn1',
                'urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress',
                '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>', u, pw);
            const ip = parseXml(r, 'NewExternalIPAddress');
            if (ip) await set('fritzbox.externalIP', ip);
        } catch (e) { this._log('WARN', 'TR064', 'WAN-IP: ' + e.message); }

        try {
            const r = await soapRequest(h, p,
                '/igdupnp/control/WANIPConn1',
                'urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo',
                '<u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>', u, pw);
            const up = parseXml(r, 'NewUptime');
            const ct = parseXml(r, 'NewConnectionType') || parseXml(r, 'NewConnectionStatus');
            if (up) await set('fritzbox.uptime', parseInt(up));
            if (ct) await set('fritzbox.connectionType', ct);
        } catch (e) { this._log('WARN', 'TR064', 'Status: ' + e.message); }

        try {
            const r = await soapRequest(h, p,
                '/tr064/upnp/control/deviceinfo',
                'urn:dslforum-org:service:DeviceInfo:1#GetInfo',
                '<u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1"/>', u, pw);
            const m = parseXml(r, 'NewModelName');
            const f = parseXml(r, 'NewSoftwareVersion');
            if (m) await set('fritzbox.modelName', m);
            if (f) await set('fritzbox.firmwareVersion', f);
        } catch (e) { this._log('WARN', 'TR064', 'DeviceInfo: ' + e.message); }

        await this._pollHosts(h, p, u, pw);
    }

    async _pollHosts(h, p, u, pw) {
        try {
            const cr = await soapRequest(h, p,
                '/tr064/upnp/control/hosts',
                'urn:dslforum-org:service:Hosts:1#GetHostNumberOfEntries',
                '<u:GetHostNumberOfEntries xmlns:u="urn:dslforum-org:service:Hosts:1"/>', u, pw);
            const count   = parseInt(parseXml(cr, 'NewHostNumberOfEntries') || '0');
            const devices = [];

            for (let i = 0; i < count; i++) {
                try {
                    const r = await soapRequest(h, p,
                        '/tr064/upnp/control/hosts',
                        'urn:dslforum-org:service:Hosts:1#GetGenericHostEntry',
                        '<u:GetGenericHostEntry xmlns:u="urn:dslforum-org:service:Hosts:1">' +
                        '<NewIndex>' + i + '</NewIndex></u:GetGenericHostEntry>', u, pw);
                    const dev = {
                        mac:    parseXml(r, 'NewMACAddress')    || '',
                        ip:     parseXml(r, 'NewIPAddress')     || '',
                        name:   parseXml(r, 'NewHostName')      || 'Unknown',
                        active: parseXml(r, 'NewActive')        === '1',
                        iface:  parseXml(r, 'NewInterfaceType') || ''
                    };
                    if (dev.mac) devices.push(dev);
                } catch (_) {}
            }

            this._cache.devices = devices;

            for (const dev of devices) {
                const pre = 'devices.' + dev.mac.replace(/[^A-Fa-f0-9]/g, '_');
                // Device-Channel anlegen
                try {
                    await this.extendObjectAsync('devices', {
                        type: 'folder', common: { name: 'Network devices' }, native: {}
                    });
                    await this.extendObjectAsync(pre, {
                        type: 'channel', common: { name: dev.name || dev.mac }, native: {}
                    });
                } catch (_) {}
                for (const [k, t, v, rl] of [
                    ['name',   'string',  dev.name,   'info.name'],
                    ['ip',     'string',  dev.ip,     'info.ip'],
                    ['mac',    'string',  dev.mac,    'info.mac'],
                    ['active', 'boolean', dev.active, 'indicator.reachable'],
                    ['iface',  'string',  dev.iface,  'text']
                ]) {
                    try {
                        await this.extendObjectAsync(pre + '.' + k, {
                            type: 'state',
                            common: { name: k, type: t, role: rl, read: true, write: false },
                            native: {}
                        });
                        await this.setStateAsync(pre + '.' + k, { val: v, ack: true });
                    } catch (_) {}
                }
            }

            this._log('INFO', 'HOSTS', count + ' devices, ' +
                devices.filter(d => d.active).length + ' active.');
        } catch (e) { this._log('WARN', 'TR064', 'Hosts: ' + e.message); }
    }

    async _pollWg() {
        const s = await wgStatus(WG_IFACE);
        this._cache.wg = s;
        await this.setStateAsync('wireguard.status', { val: s.connected ? 'connected' : 'disconnected', ack: true });
        if (s.connected && s.peers[0]) {
            const p = s.peers[0];
            await this.setStateAsync('wireguard.handshake', { val: p.handshake, ack: true });
            await this.setStateAsync('wireguard.rxBytes',   { val: p.rx,        ack: true });
            await this.setStateAsync('wireguard.txBytes',   { val: p.tx,        ack: true });
        }
        return s.connected;
    }

    async _poll() {
        try {
            const ok = await this._pollWg();
            if (ok) {
                await this._pollFritzBox();
                await this.setStateAsync('info.connection', { val: true, ack: true });
                await this.setStateAsync('info.lastUpdate', { val: new Date().toISOString(), ack: true });
            } else {
                await this.setStateAsync('info.connection', { val: false, ack: true });
                if (this.config.autoReconnect) {
                    this._log('WARN', 'WG', 'Connection lost \u2014 reconnecting \u2026');
                    await this._connectWg();
                }
            }
        } catch (e) { this._log('ERROR', 'POLL', e.message); }
    }

    // HTTP Server
    _startServer() {
        const port = parseInt(this.config.webPort) || 8094;
        this._server = http.createServer(async (req, res) => {
            const p = url.parse(req.url, true);
            const n = p.pathname;

            if (n === '/api/ping')
                return this._json(res, { ok: true, adapter: 'fritzwireguard', version: this._version() });

            if (n === '/api/status') {
                await this._pollWg();
                return this._json(res, { wg: this._cache.wg, fritzbox: this._cache.fritzbox, devices: this._cache.devices });
            }

            if (n === '/api/tunnels')
                return this._json(res, this._tunnelMgr.statusAll(this.config.tunnels || []));

            if (n === '/api/tunnels/restart' && req.method === 'POST') {
                this._tunnelMgr.stopAll();
                this._tunnelMgr.startAll(this.config.tunnels || []);
                return this._json(res, { ok: true });
            }

            if (n === '/api/logs') {
                const lv  = (p.query.level    || '').toUpperCase();
                const cat = (p.query.category || '').toUpperCase();
                let logs  = this._logBuffer.slice(0, parseInt(p.query.n) || 200);
                if (lv)  logs = logs.filter(l => l.level    === lv);
                if (cat) logs = logs.filter(l => l.category === cat);
                return this._json(res, logs);
            }

            if (n === '/api/connect'    && req.method === 'POST') return this._json(res, { ok: await this._connectWg() });
            if (n === '/api/disconnect' && req.method === 'POST') { await this._disconnectWg(); return this._json(res, { ok: true }); }
            if (n === '/api/poll'       && req.method === 'POST') { await this._poll(); return this._json(res, { ok: true }); }
            if (n === '/api/version')   return this._json(res, { installed: this._version(), name: 'fritzwireguard' });

            if (n === '/' || n === '/index.html') {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                return res.end(this._buildUI());
            }
            res.writeHead(404); res.end('Not found');
        });
        this._server.listen(port, () => {
            this._log('SYSTEM', 'SYSTEM', 'FritzWireguard v' + this._version() + ' \u2014 Port ' + port);
        });
    }

    _json(res, obj) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

    _version() { try { return require('../package.json').version; } catch (_) { return '0.2.20'; } }

    // ── Web-UI ────────────────────────────────────────────────────────────────
    _buildUI() {
        const v = this._version();
        const CSS =
':root{--bg:#0e1628;--card:#1a2744;--border:#243560;--primary:#2196F3;--accent:#00bcd4;' +
'--green:#4caf50;--red:#f44336;--yellow:#ff9800;--text:#e8eaf6;--muted:#8899bb;}' +
'*{box-sizing:border-box;margin:0;padding:0;}' +
'body{background:var(--bg);color:var(--text);font-family:"Segoe UI",sans-serif;min-height:100vh;}' +
'header{background:linear-gradient(135deg,#0a1020,#1a2744 50%,#0d1f3c);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px;}' +
'.logo{width:40px;height:40px;background:linear-gradient(135deg,var(--primary),var(--accent));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;}' +
'.title{font-size:1.4rem;font-weight:700;background:linear-gradient(90deg,var(--primary),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}' +
'.subtitle{font-size:0.78rem;color:var(--muted);}' +
'.ver{margin-left:auto;background:var(--card);border:1px solid var(--border);border-radius:20px;padding:4px 12px;font-size:0.75rem;color:var(--muted);}' +
'.pill{width:10px;height:10px;border-radius:50%;background:var(--red);box-shadow:0 0 6px var(--red);display:inline-block;margin-right:8px;}' +
'.pill.on{background:var(--green);box-shadow:0 0 6px var(--green);}' +
'nav{background:var(--card);border-bottom:1px solid var(--border);display:flex;padding:0 24px;flex-wrap:wrap;}' +
'nav button{background:none;border:none;color:var(--muted);padding:14px 18px;cursor:pointer;font-size:0.9rem;border-bottom:3px solid transparent;transition:all .2s;}' +
'nav button.active{color:var(--primary);border-bottom-color:var(--primary);}nav button:hover{color:var(--text);}' +
'.tab{display:none;padding:24px;max-width:960px;margin:0 auto;width:100%;box-sizing:border-box;}.tab.active{display:block;}' +
'.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-bottom:24px;}' +
'.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;}' +
'.ct{font-size:0.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;margin-bottom:8px;}' +
'.cv{font-size:1.5rem;font-weight:700;}.cv.green{color:var(--green);}.cv.red{color:var(--red);}' +
'.cs{font-size:0.78rem;color:var(--muted);margin-top:4px;}' +
'.table-wrap{width:100%;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;margin-bottom:20px;}' +
'table{width:100%;max-width:100%;table-layout:fixed;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;margin-bottom:0;}' +
'th{background:#1f2f50;color:var(--muted);font-size:0.72rem;text-transform:uppercase;padding:10px 12px;text-align:left;letter-spacing:.04em;}' +
'td{padding:10px 12px;border-top:1px solid var(--border);font-size:0.85rem;overflow:hidden;text-overflow:ellipsis;}' +
'tr:hover td{background:rgba(33,150,243,.05);}' +
'td.mono{font-family:ui-monospace,Consolas,monospace;font-size:0.8rem;white-space:nowrap;}' +
'table.tunnel th:nth-child(1),table.tunnel td:nth-child(1){width:22%;}' +
'table.tunnel th:nth-child(2),table.tunnel td:nth-child(2){width:16%;}' +
'table.tunnel th:nth-child(3),table.tunnel td:nth-child(3){width:20%;}' +
'table.tunnel th:nth-child(4),table.tunnel td:nth-child(4){width:12%;}' +
'table.tunnel th:nth-child(5),table.tunnel td:nth-child(5){width:16%;}' +
'table.tunnel th:nth-child(6),table.tunnel td:nth-child(6){width:14%;}' +
'.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.73rem;font-weight:600;}' +
'.badge.active,.badge.running{background:rgba(76,175,80,.18);color:var(--green);}' +
'.badge.inactive,.badge.stopped{background:rgba(244,67,54,.18);color:var(--red);}' +
'.badge.warn{background:rgba(255,152,0,.18);color:var(--yellow);}' +
'.log-area{background:#080f1e;border:1px solid var(--border);border-radius:10px;height:500px;overflow-y:auto;padding:12px;font-family:monospace;font-size:0.8rem;}' +
'.log-entry{padding:3px 0;border-bottom:1px solid rgba(36,53,96,.4);}' +
'.log-entry .ts{color:#556;margin-right:8px;}.log-entry .cat{color:var(--accent);margin-right:8px;}' +
'.log-entry.ERROR .msg{color:var(--red);}.log-entry.WARN .msg{color:var(--yellow);}.log-entry.SYSTEM .msg{color:var(--primary);}' +
'.ltb{display:flex;gap:10px;margin-bottom:12px;align-items:center;flex-wrap:wrap;}' +
'.ltb select,.ltb button{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 12px;cursor:pointer;}' +
'.btn{background:var(--primary);color:#fff;border:none;border-radius:8px;padding:10px 20px;cursor:pointer;font-size:0.88rem;font-weight:600;transition:opacity .2s;}' +
'.btn:hover{opacity:.85;}.btn.red{background:var(--red);}.btn.green{background:var(--green);}' +
'a.tunnel-link{color:var(--accent);text-decoration:none;border-bottom:1px dotted rgba(0,229,255,.4);word-break:break-all;}' +
'a.tunnel-link:hover{border-bottom-color:var(--accent);}' +
'.btn-row{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap;}' +
'.ig{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;}' +
'.ir{display:flex;justify-content:space-between;padding:8px 12px;background:#0e1628;border-radius:6px;font-size:0.85rem;}' +
'.ir .k{color:var(--muted);}.ir .v{color:var(--text);font-weight:600;}' +
'#wgbar{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}' +
'.sl{font-size:0.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;margin-bottom:12px;margin-top:8px;}' +
'.hint{background:rgba(33,150,243,.08);border:1px solid rgba(33,150,243,.25);border-radius:10px;padding:16px 20px;margin-bottom:20px;font-size:0.85rem;line-height:1.7;word-break:break-word;}' +
'.hint code{background:#0e1628;border-radius:4px;padding:2px 6px;color:var(--accent);font-family:monospace;white-space:normal;}' +
'@media(max-width:720px){' +
'  .tab{padding:16px 12px;}' +
'  nav{padding:0 8px;}' +
'  nav button{padding:12px 10px;font-size:0.8rem;}' +
'  .cards{grid-template-columns:1fr 1fr;gap:10px;}' +
'  .card{padding:14px;}' +
'  .cv{font-size:1.15rem;}' +
'  .table-wrap{overflow:visible;}' +
'  table.tunnel{table-layout:auto;background:transparent;border-radius:0;overflow:visible;}' +
'  table.tunnel thead{display:none;}' +
'  table.tunnel tbody{display:block;}' +
'  table.tunnel tr{display:block;background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;padding:8px 0;}' +
'  table.tunnel td{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;width:auto!important;border:none;padding:8px 14px;overflow:visible;text-overflow:unset;white-space:normal;word-break:break-word;}' +
'  table.tunnel td.mono{white-space:normal;}' +
'  table.tunnel td::before{content:attr(data-label);flex:0 0 38%;max-width:38%;color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:.04em;padding-top:2px;}' +
'  table.tunnel td > *{text-align:right;}' +
'  table.nodes thead{display:none;}' +
'  table.nodes,table.nodes tbody,table.nodes tr,table.nodes td{display:block;width:auto!important;}' +
'  table.nodes{background:transparent;}' +
'  table.nodes tr{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:12px;padding:8px 0;}' +
'  table.nodes td{border:none;padding:8px 14px;overflow:visible;text-overflow:unset;white-space:normal;word-break:break-word;}' +
'  table.nodes td::before{content:attr(data-label);display:block;color:var(--muted);font-size:0.68rem;text-transform:uppercase;margin-bottom:2px;}' +
'  .log-area{height:360px;}' +
'  .ig{grid-template-columns:1fr;}' +
'}';

        const JS =
'function showTab(n){' +
'  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active");});' +
'  document.querySelectorAll("nav button").forEach(function(b){b.classList.remove("active");});' +
'  var el=document.getElementById("tab-"+n);if(el)el.classList.add("active");' +
'  var btn=document.getElementById("tb-"+n);if(btn)btn.classList.add("active");' +
'  if(n==="logs")loadLogs();if(n==="tunnel")loadTunnels();if(n==="data")loadStatus();if(n==="nodes")loadStatus();if(n==="system")loadStatus();' +
'}' +
'function fmt(b){if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";return (b/1048576).toFixed(2)+" MB";}' +
'function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}' +
'function card(t,v,sub,cls){return "<div class=\'card\'><div class=\'ct\'>"+t+"</div><div class=\'cv "+(cls||"")+"\'>"+v+"</div>"+(sub?"<div class=\'cs\'>"+sub+"</div>":"")+"</div>";}' +
'function ir(k,v){return "<div class=\'ir\'><span class=\'k\'>"+k+"</span><span class=\'v\'>"+v+"</span></div>";}' +
'async function loadStatus(){' +
'  try{var r=await fetch("/api/status");var d=await r.json();' +
'  var wg=d.wg||{};var fb=d.fritzbox||{};var devs=d.devices||[];' +
'  var pill=document.getElementById("wg-pill");var txt=document.getElementById("wg-txt");' +
'  if(wg.connected){pill.className="pill on";txt.textContent="WireGuard verbunden";}' +
'  else{pill.className="pill";txt.textContent="WireGuard getrennt";}' +
'  document.getElementById("lu").textContent="Stand: "+new Date().toLocaleTimeString();' +
'  var wgC="";var peer=wg.peers&&wg.peers[0]?wg.peers[0]:{};' +
'  wgC+=card("Status",wg.connected?"Verbunden":"Getrennt","",wg.connected?"green":"red");' +
'  if(peer.handshake)wgC+=card("Letzter Handshake",peer.handshake,"","");' +
'  if(peer.rx!=null)wgC+=card("Empfangen",fmt(peer.rx),"","");' +
'  if(peer.tx!=null)wgC+=card("Gesendet",fmt(peer.tx),"","");' +
'  document.getElementById("cards-wg").innerHTML=wgC;' +
'  var fbC="";' +
'  if(fb.externalIP)fbC+=card("Externe IP",fb.externalIP,"","");' +
'  if(fb.modelName)fbC+=card("Modell",fb.modelName,"","");' +
'  if(fb.firmwareVersion)fbC+=card("Firmware",fb.firmwareVersion,"","");' +
'  if(fb.uptime!=null)fbC+=card("Uptime",Math.floor(fb.uptime/3600)+"h "+Math.floor((fb.uptime%3600)/60)+"m","","");' +
'  document.getElementById("cards-fritz").innerHTML=fbC;' +
'  var tb="";devs.sort(function(a,b){return b.active-a.active;}).forEach(function(dv){' +
'    tb+="<tr><td data-label=\'Name\'>"+esc(dv.name)+"</td><td data-label=\'IP\'>"+esc(dv.ip)+"</td>"' +
'      +"<td data-label=\'MAC\' style=\'font-family:monospace\'>"+esc(dv.mac)+"</td>"' +
'      +"<td data-label=\'Interface\'>"+esc(dv.iface)+"</td>"' +
'      +"<td data-label=\'Status\'><span class=\'badge "+(dv.active?"active":"inactive")+"\'>"+(dv.active?"Aktiv":"Inaktiv")+"</span></td></tr>";});' +
'  var nb=document.getElementById("nbody");' +
'  if(nb)nb.innerHTML=tb||"<tr><td colspan=\'5\' style=\'text-align:center;color:var(--muted)\'>Keine Ger\u00e4te</td></tr>";' +
'  var si=document.getElementById("sinfo");' +
'  if(si)si.innerHTML=ir("Adapter","FritzWireguard")+ir("Version","' + v + '")' +
'    +ir("Ger\u00e4te",devs.length)+ir("Aktiv",devs.filter(function(dv){return dv.active;}).length);' +
'  }catch(e){console.error(e);}' +
'}' +
'async function loadTunnels(){' +
'  try{var r=await fetch("/api/tunnels");var ts=await r.json();' +
'  var tb="";ts.forEach(function(t){' +
'    var st=t.error?"warn":(t.running?"running":"stopped");' +
'    var stTxt=t.error?"Fehler":(t.running?"Aktiv":"Gestoppt");' +
'    var openUrl=t.exposeLan&&t.lanIp?("http://"+t.lanIp+":"+t.localPort+"/"):"";' +
'    var localInner;' +
'    if(openUrl){' +
'      localInner="<a class=\'tunnel-link mono\' href=\'"+esc(openUrl)+"\' target=\'_blank\' rel=\'noopener\' title=\'Wechselrichter-Web-UI \u00f6ffnen\'>"' +
'        +esc(t.lanIp+":"+t.localPort)+" (LAN)</a>";' +
'    }else{' +
'      localInner="<span class=\'mono\' title=\'Nur lokal f\u00fcr Adapter auf diesem Host\'>127.0.0.1:"+esc(t.localPort)+"</span>";' +
'    }' +
'    tb+="<tr><td data-label=\'Name\' title=\'"+esc(t.name)+"\'><strong>"+esc(t.name)+"</strong></td>"' +
'      +"<td data-label=\'Lokal\'>"+localInner+"</td>"' +
'      +"<td class=\'mono\' data-label=\'Ziel\' title=\'"+esc(t.remoteHost)+":"+esc(t.remotePort)+"\'>"+esc(t.remoteHost)+":"+esc(t.remotePort)+"</td>"' +
'      +"<td data-label=\'Verb.\'>"+t.active+"/"+t.total+"</td>"' +
'      +"<td class=\'mono\' data-label=\'Traffic\'>"+fmt(t.rxBytes)+" / "+fmt(t.txBytes)+"</td>"' +
'      +"<td data-label=\'Status\'><span class=\'badge "+st+"\'>"+stTxt+"</span>"' +
'      +(t.error?"<br><small style=\'color:var(--red)\'>"+esc(t.error)+"</small>":"")+"</td></tr>";' +
'  });' +
'  var tbody=document.getElementById("tbody-tunnel");' +
'  if(tbody)tbody.innerHTML=tb||"<tr><td colspan=\'6\' style=\'text-align:center;color:var(--muted)\'>Keine Tunnel konfiguriert</td></tr>";}' +
'  catch(e){console.error(e);}' +
'}' +
'async function restartTunnels(){await fetch("/api/tunnels/restart",{method:"POST"});loadTunnels();}' +
'async function loadLogs(){' +
'  var lv=document.getElementById("ll").value;var cat=document.getElementById("lc").value;' +
'  var r=await fetch("/api/logs?n=300&level="+encodeURIComponent(lv)+"&category="+encodeURIComponent(cat));' +
'  var logs=await r.json();' +
'  var html=logs.map(function(l){var d=new Date(l.ts);' +
'    return "<div class=\'log-entry "+(l.level||"")+"\'><span class=\'ts\'>"+d.toLocaleDateString()+" "+d.toLocaleTimeString()+"</span>"' +
'      +"<span class=\'cat\'>"+esc(l.category)+"</span><span class=\'msg\'>"+esc(l.msg)+"</span></div>";}).join("");' +
'  var la=document.getElementById("la");la.innerHTML=html||"<span style=\'color:var(--muted)\'>Keine Eintr\u00e4ge</span>";' +
'  if(document.getElementById("lauto").checked)la.scrollTop=la.scrollHeight;}' +
'function exportLogs(){var blob=new Blob([document.getElementById("la").innerText],{type:"text/plain"});' +
'  var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="fritzwireguard-logs.txt";a.click();}' +
'async function wgConnect(){document.getElementById("smsg").textContent="Verbinde\u2026";' +
'  var d=await(await fetch("/api/connect",{method:"POST"})).json();' +
'  document.getElementById("smsg").textContent=d.ok?"Verbunden.":"Fehler.";loadStatus();}' +
'async function wgDisconnect(){document.getElementById("smsg").textContent="Trenne\u2026";' +
'  await fetch("/api/disconnect",{method:"POST"});document.getElementById("smsg").textContent="Getrennt.";loadStatus();}' +
'async function forcePoll(){document.getElementById("smsg").textContent="Abfrage\u2026";' +
'  await fetch("/api/poll",{method:"POST"});document.getElementById("smsg").textContent="Fertig.";loadStatus();}' +
'loadStatus();window["setInterval"](loadStatus,30000);';

        return '<!DOCTYPE html><html lang="de"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
'<title>FritzWireguard</title><style>' + CSS + '</style></head><body>' +
'<header><div class="logo">\uD83D\uDD12</div>' +
'<div><div class="title">FritzWireguard</div><div class="subtitle">WireGuard VPN \u2192 FritzBox</div></div>' +
'<div class="ver">v' + v + '</div></header>' +
'<nav>' +
'<button id="tb-daten"  class="active" onclick="showTab(\'daten\')">&#128202; Daten</button>' +
'<button id="tb-nodes"  onclick="showTab(\'nodes\')">&#128268; Nodes</button>' +
'<button id="tb-tunnel" onclick="showTab(\'tunnel\')">&#128260; Tunnel</button>' +
'<button id="tb-logs"   onclick="showTab(\'logs\')">&#128203; Logs</button>' +
'<button id="tb-system" onclick="showTab(\'system\')">&#9881;&#65039; System</button>' +
'</nav>' +

// TAB: DATEN
'<div class="tab active" id="tab-daten">' +
'<div id="wgbar"><span class="pill" id="wg-pill"></span><strong id="wg-txt">Lade\u2026</strong>' +
'<span style="margin-left:auto;color:var(--muted);font-size:0.8rem" id="lu"></span></div>' +
'<div class="sl">WireGuard</div><div class="cards" id="cards-wg"></div>' +
'<div class="sl">FritzBox</div><div class="cards" id="cards-fritz"></div>' +
'</div>' +

// TAB: NODES
'<div class="tab" id="tab-nodes">' +
'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
'<h2 style="font-size:1rem;color:var(--muted);">Netzwerkger\u00e4te im entfernten Netz</h2>' +
'<button class="btn" onclick="loadStatus()">&#8635; Aktualisieren</button></div>' +
'<div class="table-wrap"><table class="nodes"><thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Interface</th><th>Status</th></tr></thead>' +
'<tbody id="nbody"><tr><td colspan="5" style="text-align:center;color:var(--muted)">Lade\u2026</td></tr></tbody></table></div>' +
'</div>' +

// TAB: TUNNEL
'<div class="tab" id="tab-tunnel">' +
'<div class="hint"><strong style="color:var(--primary)">&#128260; TCP Port-Weiterleitung durch den VPN-Tunnel</strong><br>' +
'Jeder Tunnel \u00f6ffnet einen Port und leitet Verbindungen durch WireGuard weiter.<br>' +
'Standard: nur <code>127.0.0.1</code> (f\u00fcr Adapter auf diesem Host). Mit <b>LAN-Zugriff</b> auch von Handy/PC \u00fcber die Host-IP.<br>' +
'Andere Adapter: Feld <b>IP/Host</b> = <code>127.0.0.1</code>, Feld <b>Port</b> = lokaler Tunnel-Port (getrennt!).<br>' +
'Nicht <code>127.0.0.1:8085</code> in ein einziges Feld schreiben \u2014 das schl\u00e4gt DNS fehl.<br><br>' +
'<strong>Beispiel Kostal Piko:</strong> Ziel <code>192.168.178.30:80</code> &rarr; Tunnel-Port <code>8085</code> &rarr; ' +
'Kostal: IP <code>127.0.0.1</code>, Port <code>8085</code>. Mit LAN-Zugriff: Handy \u2192 <code>http://&lt;Host-IP&gt;:8085/</code>.' +
'</div>' +
'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;gap:12px;flex-wrap:wrap;">' +
'<div class="sl" style="margin:0">Konfigurierte Tunnel</div>' +
'<button class="btn" onclick="restartTunnels()">&#8635; Tunnel neu starten</button></div>' +
'<div class="table-wrap"><table class="tunnel"><thead><tr>' +
'<th>Name</th><th>Lokal</th><th>Ziel</th>' +
'<th>Verb.</th><th>Traffic</th><th>Status</th></tr></thead>' +
'<tbody id="tbody-tunnel"><tr><td colspan="6" style="text-align:center;color:var(--muted)">Lade\u2026</td></tr></tbody></table></div>' +
'<p style="font-size:0.82rem;color:var(--muted)">Tunnel werden in der Adapter-Konfiguration (ioBroker Admin \u2192 Instanz) eingerichtet. Lokal = Port auf 127.0.0.1.</p>' +
'</div>' +

// TAB: LOGS
'<div class="tab" id="tab-logs">' +
'<div class="ltb">' +
'<select id="ll"><option value="">Alle Level</option>' +
'<option>SYSTEM</option><option>INFO</option><option>WARN</option><option>ERROR</option></select>' +
'<select id="lc"><option value="">Alle Kategorien</option>' +
'<option value="WG">WireGuard</option><option value="TR064">TR-064</option>' +
'<option value="HOSTS">Hosts</option><option value="TUNNEL">Tunnel</option>' +
'<option value="POLL">Poll</option><option value="SYSTEM">System</option></select>' +
'<button onclick="loadLogs()">&#8635; Neu laden</button>' +
'<button onclick="exportLogs()">&#8595; Export</button>' +
'<label style="margin-left:auto;font-size:0.8rem;display:flex;gap:6px;align-items:center;">' +
'<input type="checkbox" id="lauto" checked> Auto-Scroll</label>' +
'</div><div class="log-area" id="la"></div></div>' +

// TAB: SYSTEM
'<div class="tab" id="tab-system">' +
'<div class="card" style="margin-bottom:20px;"><div class="ct">WireGuard Steuerung</div>' +
'<div class="btn-row">' +
'<button class="btn green" onclick="wgConnect()">Verbinden</button>' +
'<button class="btn red"   onclick="wgDisconnect()">Trennen</button>' +
'<button class="btn"       onclick="forcePoll()">&#8635; Jetzt abfragen</button>' +
'</div><div id="smsg" style="margin-top:12px;font-size:0.85rem;color:var(--muted);"></div></div>' +
'<div class="card"><div class="ct">Adapter-Info</div><div class="ig" id="sinfo"></div></div>' +
'</div>' +

'<script>' + JS + '</script></body></html>';
    }

    // Lifecycle
    async onReady() {
        try {
            _dbg('onReady() started, config: ' + JSON.stringify({webPort: this.config && this.config.webPort, autoConnect: this.config && this.config.autoConnect}));
            this._log('SYSTEM', 'SYSTEM', 'FritzWireguard v' + this._version() + ' starting \u2026');
            await this._initStates();

            this._tunnelMgr = new TunnelManager(this._log.bind(this));
            this._tunnelMgr.startAll(this.config.tunnels || []);

            this._startServer();
            if (this.config.autoConnect) await this._connectWg();
            await this._poll();

            const iv = Math.max(30, parseInt(this.config.pollInterval) || 60);
            this._pollTimer = this.setInterval(() => this._poll(), iv * 1000);
            this._log('SYSTEM', 'SYSTEM', 'FritzWireguard ready. Poll interval: ' + iv + 's');
        } catch (e) {
            // Fehler loggen aber Adapter NICHT beenden - sonst NO_ERROR termination
            _dbg('FEHLER in onReady: ' + e.message + '\n' + e.stack);
            console.error('[FRITZWIREGUARD] Kritischer Fehler in onReady:', e);
            const l = this.log;
            if (l) l.error('[SYSTEM] Kritischer Fehler in onReady: ' + e.message + ' | Stack: ' + e.stack);
            // Sicherstellen dass Poll-Timer laeuft damit Prozess am Leben bleibt
            if (!this._pollTimer) {
                const iv = Math.max(30, parseInt((this.config && this.config.pollInterval)) || 60);
                this._pollTimer = this.setInterval(() => this._poll(), iv * 1000);
            }
        }
    }
    onStateChange(id, state) {
        if (state && !state.ack) this._log('INFO', 'STATE', id + ' = ' + state.val);
    }

    onUnload(callback) {
        _dbg('onUnload() called');
        // callback SOFORT aufrufen - kein async, kein warten
        // ioBroker hat sehr kurzen Timeout (< 1s bei force-stop)
        // Alles synchron + fire-and-forget
        try {
            if (this._pollTimer) { this.clearInterval(this._pollTimer); this._pollTimer = null; }
            if (this._tunnelMgr) { this._tunnelMgr.stopAll(); }
            if (this._server) {
                try {
                    if (typeof this._server.closeAllConnections === 'function')
                        this._server.closeAllConnections();
                    this._server.close();
                } catch (_) {}
                this._server = null;
            }
            // Temp-Config loeschen (synchron)
            if (this._wgCfgPath) {
                try {
                    if (fs.existsSync(this._wgCfgPath)) fs.unlinkSync(this._wgCfgPath);
                } catch (_) {}
            }
        } catch (_) {}

        // callback sofort - VOR wg-quick down (der laeuft fire-and-forget)
        callback();

        // wg-quick down als fire-and-forget NACH callback
        const wgDisconnect = this.config && this.config.wgDisconnectOnStop;
        const cfgPath = this._wgCfgPath;
        if (wgDisconnect && cfgPath) {
            execWg('wg-quick down ' + cfgPath).catch(() => {});
        }
    }
}

const _logic = new FritzWireguardLogic();

function initInstance(adapter) {
    adapter._server    = null;
    adapter._logBuffer = [];
    adapter._pollTimer = null;
    adapter._wgCfgPath = null;
    adapter._cache     = { wg: {}, fritzbox: {}, devices: [] };
    adapter._tunnelMgr = null;
    for (const name of Object.getOwnPropertyNames(FritzWireguardLogic.prototype)) {
        if (name === 'constructor') continue;
        const fn = _logic[name];
        if (typeof fn === 'function') adapter[name] = fn.bind(adapter);
    }
}

function runReady(adapter)       { return adapter.onReady(); }
function runUnload(adapter, cb)  { return adapter.onUnload(cb); }
function runStateChange(a, id, s){ return a.onStateChange(id, s); }
function runMessage(adapter, obj){ return adapter.onMessage(obj); }

module.exports = { initInstance, runReady, runUnload, runStateChange, runMessage };
