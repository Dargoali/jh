import { readFileSync, writeFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import axios from 'axios';
import chalk from 'chalk';

// Setup crypto required by cantor8 network
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// =========================================================================
// CONFIGURATION
// =========================================================================
const TARGET_ADDRESS = ""; // GANTI ADDRESS TUJUAN DISINI
const MINIMUM_BALANCE_TO_SEND = 5; // Minimum balance CC to trigger auto send
const RETAINED_FEE = 1; // Saldo CC yang disisakan untuk buffer fee
const CHECK_INTERVAL_MINUTES = 1; // How often to check balances (set to 0 for single run)
// =========================================================================

const BACKEND_URL = "https://wallet-backend.main.digik.cantor8.tech/api";
const ACCOUNTS_FILE = new URL('./accounts.json', import.meta.url);

const BASE_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Origin': 'https://wallet.cantor8.tech',
    'Referer': 'https://wallet.cantor8.tech/',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
};

// --- Utilities ---
const sleep = (sec) => new Promise(r => setTimeout(r, sec * 1000));
function toHex(bytes) { return Buffer.from(bytes).toString('hex'); }
function toBase64(bytes) { return Buffer.from(bytes).toString('base64'); }
function shortId(id) { return id.length > 20 ? `${id.slice(0, 12)}...${id.slice(-8)}` : id; }

function generateOrderId() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = randomBytes(20);
    let id = 'ord_';
    for (let i = 0; i < 20; i++) id += chars[bytes[i] % chars.length];
    return id;
}

// --- Crypto ---
function generateKeyPairs(mnemonic) {
    const seed = mnemonicToSeedSync(mnemonic, '');
    const hdkey = HDKey.fromMasterSeed(seed);
    const keys = [];
    // Only derive the first 5 keys, usually balance is on the first one
    for (let i = 0; i < 5; i++) {
        const path = `m/501'/800245900'/0'/0'/${i}'`;
        const child = hdkey.derive(path);
        const privateKey = child.privateKey;
        const publicKey = ed.getPublicKey(privateKey);
        keys.push({
            privateKey,
            publicKeyHex: Buffer.from(publicKey).toString('hex')
        });
    }
    return keys;
}

function signMessage(privateKey, message) {
    const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    return ed.sign(msg, privateKey);
}

// --- API Client ---
function createWalletApi() {
    const ax = axios.create({ timeout: 30000 });
    const h = BASE_HEADERS;
    const auth = (token) => ({ ...h, Authorization: `Bearer ${token}` });
    return {
        recoverAccount: (keys) => ax.post(`${BACKEND_URL}/accounts/recovery_v3`, { public_keys: keys }, { headers: h }).then(r => r.data),
        getChallenge: (pid) => ax.post(`${BACKEND_URL}/auth/challenge`, { party_id: pid }, { headers: h }).then(r => r.data),
        login: (pid, ch, sig) => ax.post(`${BACKEND_URL}/auth/login`, { party_id: pid, challenge: ch, signature: sig }, { headers: h }).then(r => r.data),
        getBalance: (token) => ax.get(`${BACKEND_URL}/balance`, { headers: auth(token) }).then(r => r.data),
        prepareTransfer: (token, body) =>
            ax.post(`${BACKEND_URL}/transfer/prepare`, {
                instrument_admin_id: body.instrumentAdminId,
                instrument_id: body.instrumentId,
                receiver_party_id: body.receiverPartyId,
                amount: body.amount,
                reason: body.reason || '',
                app_name: body.appName || 'auto-send',
                metadata: body.metadata || {}
            }, { headers: auth(token) }).then(r => r.data),
        executeTransaction: (token, body) =>
            ax.post(`${BACKEND_URL}/transaction/execute`, {
                command_id: body.commandId,
                prepared_tx_b64: body.preparedTxB64,
                hashing_scheme_version: body.hashingSchemeVersion,
                signature_b64: body.signatureB64,
            }, { headers: auth(token) }).then(r => r.data),
        getTransferStatus: (token, commandId) =>
            ax.get(`${BACKEND_URL}/transfer/status`, { params: { command_id: commandId }, headers: auth(token) }).then(r => r.data)
    };
}

// --- Main Flow ---
async function processAccount(mnemonic, accountName) {
    const api = createWalletApi();

    console.log(chalk.cyan(`\n[${accountName}] Processing account...`));
    try {
        // 1. Derive Keys
        const keyPairs = generateKeyPairs(mnemonic);

        // 2. Recover Account
        const recovery = await api.recoverAccount(keyPairs.map(k => k.publicKeyHex));
        const matchIdx = (recovery.results || []).findIndex(r => r !== null);
        if (matchIdx === -1) {
            console.log(chalk.red(`[${accountName}] ❌ No active account found for this mnemonic.`));
            return;
        }

        const partyId = recovery.results[matchIdx].party_id;
        const keyPair = keyPairs[matchIdx];
        console.log(chalk.gray(`[${accountName}] 🆔 Party ID: ${partyId}`));

        // 3. Login
        const { challenge } = await api.getChallenge(partyId);
        const sig = toHex(signMessage(keyPair.privateKey, challenge));
        const { access_token } = await api.login(partyId, challenge, sig);
        console.log(chalk.green(`[${accountName}] ✅ Logged in securely.`));

        // 4. Check Balance
        const { holdings } = await api.getBalance(access_token);
        const amuletOpts = ['Amulet', 'CC', 'CC (Amulet)'];
        let ccBalance = 0;
        let instrumentAdminId = '';

        for (const opt of amuletOpts) {
            if (holdings && holdings[opt] && holdings[opt].balance !== undefined) {
                ccBalance = holdings[opt].balance;
                instrumentAdminId = holdings[opt].instrument_admin_id;
                break;
            }
        }

        console.log(chalk.yellow(`[${accountName}] 💰 Balance CC: ${ccBalance.toFixed(4)}`));

        // 5. Check Threshold
        if (ccBalance >= MINIMUM_BALANCE_TO_SEND) {
            const amountToSend = ccBalance - RETAINED_FEE;

            if (amountToSend <= 0) {
                console.log(chalk.yellow(`[${accountName}] ⚠️ Balance ${ccBalance} CC dipotong fee ${RETAINED_FEE} CC menjadi <= 0. Skip.`));
                return;
            }

            console.log(chalk.green(`[${accountName}] 🚀 Balance >= ${MINIMUM_BALANCE_TO_SEND}, preparing to send ${amountToSend.toFixed(4)} CC (Sisa fee: ${RETAINED_FEE} CC)...`));

            // 6. Request Prepare Transfer
            const prepareRes = await api.prepareTransfer(access_token, {
                instrumentAdminId: instrumentAdminId,
                instrumentId: "Amulet", // Standard C8 instrument ID for CC
                receiverPartyId: TARGET_ADDRESS,
                amount: amountToSend,
                reason: 'AutoSendReward'
            });

            const commandId = prepareRes.command_id || prepareRes.commandId;
            const preparedTxB64 = prepareRes.prepared_tx_b64 || prepareRes.preparedTxB64;
            const hashB64 = prepareRes.hash_b64 || prepareRes.hashB64;
            const hashingSchemeVersion = prepareRes.hashing_scheme_version || prepareRes.hashingSchemeVersion || 'HASHING_SCHEME_VERSION_V2';

            if (!preparedTxB64 || !hashB64) {
                throw new Error("Invalid prepare response, missing prepared_tx or hash");
            }

            // 7. Sign and Execute
            const signature = signMessage(keyPair.privateKey, Buffer.from(hashB64, 'base64'));

            console.log(chalk.gray(`[${accountName}] ✍️ Signing transaction...`));
            await api.executeTransaction(access_token, {
                commandId,
                preparedTxB64,
                signatureB64: toBase64(signature),
                hashingSchemeVersion
            });

            console.log(chalk.green(`[${accountName}] ✅ Execute Payload Sent! Waiting for confirmation...`));

            // 8. Poll Confirmation
            for (let i = 0; i < 10; i++) {
                await sleep(3);
                try {
                    const txStatus = await api.getTransferStatus(access_token, commandId);
                    if (txStatus.status === 'success') {
                        console.log(chalk.blue.bold(`[${accountName}] 🎉 Sukses! Reward ${amountToSend.toFixed(4)} CC berhasil dikirim ke alamat tujuan.`));
                        return;
                    }
                } catch (e) {
                    continue;
                }
            }
            console.log(chalk.yellow(`[${accountName}] ⚠️ Swap dikirim ke blockchain, tapi check status timeout.`));
        } else {
            console.log(chalk.gray(`[${accountName}] ⏩ Skip. Balance ${ccBalance} dibawah minimum send limit (${MINIMUM_BALANCE_TO_SEND})`));
        }

    } catch (err) {
        console.log(chalk.red(`[${accountName}] ❌ Error: ${err.message}`));
        if (err.response && err.response.data) {
            console.log(chalk.red(`[${accountName}] ❌ Detail: ${JSON.stringify(err.response.data)}`));
        }
    }
}

async function start() {
    process.stdout.write('\x1B[H\x1B[2J');
    console.log(chalk.cyan.bold(`  🤖 C8 AUTO SEND SCRIPT\n`));

    while (true) {
        try {
            const rawAccounts = readFileSync(ACCOUNTS_FILE, 'utf-8');
            const mnemonics = rawAccounts.split('\n').map(l => l.trim()).filter(l => l.length > 0);

            if (mnemonics.length === 0) {
                console.log(chalk.red('❌ Tidak ada mnemonic di accounts.json!'));
                return;
            }

            console.log(chalk.gray(`📋 Ditemukan ${mnemonics.length} akun...`));

            for (let i = 0; i < mnemonics.length; i++) {
                await processAccount(mnemonics[i], `Akun ${i + 1}`);
                if (i < mnemonics.length - 1) await sleep(2); // Short delay between accounts
            }

        } catch (err) {
            console.error(chalk.red('\nSistem Error:'), err.message);
        }

        if (CHECK_INTERVAL_MINUTES <= 0) {
            console.log(chalk.green('\n🏁 Proses selesai! (Single Run Mode)'));
            break;
        }

        console.log(chalk.gray(`\n💤 Menunggu ${CHECK_INTERVAL_MINUTES} menit sebelum scan berikutnya...`));
        await sleep(CHECK_INTERVAL_MINUTES * 60);
    }
}

start();
