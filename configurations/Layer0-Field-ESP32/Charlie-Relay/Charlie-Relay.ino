#include <WiFi.h>
#include <esp_mac.h>
#include <time.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <WebServer.h>
#include <Update.h>
#include "aes_gcm_wrapper.h"
#include "ecdh_kex.h"
#include "classical_server_cert.h"

// ==========================================
// CONFIGURAÇÕES GERAIS (FASE CHARLIE)
// ==========================================
const char* ssid     = "ViPeR5000-Charlie";
const char* password = "0000011111";

#define FIRMWARE_VERSION  "1.0.0-SR-AES128GCM"
#define FIRMWARE_TYPE     "Charlie-Relay"
#define BUILD_TIMESTAMP   __DATE__ " " __TIME__
const char* ota_user = "admin";
const char* ota_pass = "msi-tese";

#ifdef CLASSICAL_CERT_READY
const char* kex_server_url = "https://192.168.30.200:8000/kex/exchange";
#else
const char* kex_server_url = "http://192.168.30.200:8000/kex/exchange";
#endif

const char* mqtt_server = "192.168.30.100";
const int   mqtt_port   = 1883;

#define RELAY_PIN 18

WiFiClient   espClient;
PubSubClient mqttClient(espClient);
AesGcmWrapper aesGcm;
WebServer statusServer(80);

String macHex = "";
String topic_command = "";
String topic_status  = "";
String topic_metrics = "";

bool current_relay_state = false;

unsigned long last_key_rotation = 0;
unsigned long last_kex_attempt  = 0;
unsigned long last_telemetry    = 0;
const unsigned long KEY_ROTATION_INTERVAL = 3600000;
const unsigned long KEX_RETRY_INTERVAL    = 30000;
const unsigned long TELEMETRY_INTERVAL    = 5000;

String        topic_handshake = "";
float         hs_latency_ms = 0;
unsigned int  hs_req_bytes  = 0;
unsigned int  hs_resp_bytes = 0;
bool          hs_pending    = false;
bool kex_completed = false;

// Monitor de performance (AES-128-GCM) — igual aos sensores
unsigned long total_bytes_sent = 0, packets_sent = 0, packets_received = 0;
unsigned long last_publish_micros = 0; bool waiting_for_ack = false;
#define MAX_SAMPLES 20
float latency_samples[MAX_SAMPLES]; int sample_idx = 0, num_samples = 0;
float avg_latency = 0, current_jitter = 0;
unsigned long deadline_violations = 0, telemetry_sessions = 0;
float crypto_cpu_overhead_us = 0, crypto_ram_overhead_kb = 0;
const unsigned long config_deadline_ms = 2000;

// Buffer de logs em memória (consola do dashboard)
#define LOG_SIZE 15
String event_logs[LOG_SIZE];
int log_ptr = 0;
void addLog(String msg) {
    struct tm ti; char ts[10];
    if (getLocalTime(&ti)) strftime(ts, sizeof(ts), "%H:%M:%S", &ti);
    else strcpy(ts, "--:--:--");
    String entry = "[" + String(ts) + "] " + msg;
    event_logs[log_ptr] = entry;
    log_ptr = (log_ptr + 1) % LOG_SIZE;
    Serial.println(entry);
}

String getMacHex() {
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char s[13]; snprintf(s, sizeof(s), "%02X%02X%02X%02X%02X%02X",
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return String(s);
}

void setup_wifi() {
    Serial.printf("[WiFi] A ligar a %s ", ssid);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.println("\n[WiFi] IP: " + WiFi.localIP().toString());
}

void perform_kex() {
    Serial.println("[KEX] Iniciando ECDH secp384r1...");
    if (WiFi.status() != WL_CONNECTED) { Serial.println("[KEX] Sem WiFi."); return; }

    EcdhKex kex;
    String cpub = kex.genPublic();
    if (cpub.isEmpty()) { Serial.println("[KEX] Falha ao gerar chave."); return; }

    HTTPClient http;
#ifdef CLASSICAL_CERT_READY
    WiFiClientSecure nc; nc.setTimeout(15); nc.setCACert(CLASSICAL_SERVER_CERT);
    http.begin(nc, kex_server_url);
#else
    WiFiClient nc; http.begin(nc, kex_server_url);
    Serial.println("[KEX] HTTP sem TLS.");
#endif
    http.addHeader("Content-Type", "application/json");

    StaticJsonDocument<256> req;
    req["node_id"] = macHex; req["client_pub_b64"] = cpub;
    String body; serializeJson(req, body);

    unsigned long hs_t0 = millis();
    int code = http.POST(body);
    if (code == 200) {
        String response = http.getString();
        hs_latency_ms = (float)(millis() - hs_t0);
        hs_req_bytes  = body.length();
        hs_resp_bytes = response.length();
        StaticJsonDocument<256> res;
        if (!deserializeJson(res, response) && res["server_pub_b64"]) {
            uint8_t key[16];
            if (kex.deriveKey(res["server_pub_b64"], key)) {
                aesGcm.setKey(key, 16);
                kex_completed = true;
                last_key_rotation = millis();
                hs_pending = true;
                Serial.println("[KEX] Chave AES-128-GCM OK.");
            } else Serial.println("[KEX] Falha HKDF.");
        } else Serial.println("[KEX] JSON inválido.");
    } else {
        Serial.printf("[KEX] Falha HTTP %d\n", code);
        kex_completed = false;
    }
    http.end();
}

bool tracked_publish(const char* topic, const char* payload) {
    total_bytes_sent += strlen(topic) + strlen(payload) + 2;
    packets_sent++;
    return mqttClient.publish(topic, payload);
}

void update_telemetry_stats(float lat_ms) {
    packets_received++;
    latency_samples[sample_idx] = lat_ms;
    sample_idx = (sample_idx + 1) % MAX_SAMPLES;
    if (num_samples < MAX_SAMPLES) num_samples++;
    float sum = 0, sq = 0;
    for (int i = 0; i < num_samples; i++) sum += latency_samples[i];
    avg_latency = sum / num_samples;
    for (int i = 0; i < num_samples; i++) sq += pow(latency_samples[i] - avg_latency, 2);
    current_jitter = sqrt(sq / num_samples);
}

// Aplica um estado ao relé físico e publica o novo estado (com loopback p/ latência)
void set_relay(bool on, const char* origem) {
    current_relay_state = on;
    digitalWrite(RELAY_PIN, on ? HIGH : LOW);
    addLog(String("Relé ") + (on ? "LIGADO" : "DESLIGADO") + " (" + origem + ")");
    if (!kex_completed) return;
    StaticJsonDocument<256> doc;
    doc["node"]   = macHex;
    doc["fw"]     = FIRMWARE_VERSION;
    doc["relay"]  = on ? 1 : 0;
    doc["status"] = on ? "LIGADO" : "DESLIGADO";
    String plain; serializeJson(doc, plain);
    last_publish_micros = micros(); waiting_for_ack = true;
    tracked_publish(topic_status.c_str(), aesGcm.encrypt(plain).c_str());
}

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    String t = String(topic);
    String blob = ""; for (unsigned int i = 0; i < length; i++) blob += (char)payload[i];

    // Loopback: eco do próprio estado → latência/jitter
    if (t == topic_status && waiting_for_ack) {
        float lat = (micros() - last_publish_micros) / 1000.0;
        waiting_for_ack = false;
        update_telemetry_stats(lat);
        return;
    }

    // Comando cifrado AES-GCM: {"command":"relay_on"|"relay_off"}
    if (t == topic_command && kex_completed) {
        String pt = aesGcm.decrypt(blob);
        if (pt.isEmpty()) { addLog("Comando: decrypt falhou"); return; }
        StaticJsonDocument<128> cmd;
        if (deserializeJson(cmd, pt)) { addLog("Comando: JSON inválido"); return; }
        String c = String((const char*)(cmd["command"] | ""));
        if (c == "relay_on")  set_relay(true,  "MQTT");
        else if (c == "relay_off") set_relay(false, "MQTT");
    }
}

void connect_mqtt() {
    while (!mqttClient.connected()) {
        Serial.printf("[MQTT] A ligar como %s...", macHex.c_str());
        if (mqttClient.connect(macHex.c_str())) {
            Serial.println(" OK");
            mqttClient.subscribe(topic_command.c_str());
            mqttClient.subscribe(topic_status.c_str());  // loopback p/ latência
            addLog("MQTT ligado — subscrito comando + estado");
        } else { Serial.printf(" rc=%d, retry 5s\n", mqttClient.state()); delay(5000); }
    }
}

void handleStatus() {
    // Dashboard glassmorphic — mesmo layout dos sensores, tema cinzento (Charlie).
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<meta http-equiv='refresh' content='5'>";
    html += "<title>ViPeR Charlie - Relay</title><style>";
    html += "body{font-family:'Outfit',sans-serif;background:#0d0e12;color:#e2e8f0;margin:0;padding:20px;display:flex;flex-direction:column;align-items:center;min-height:100vh;}";
    html += ".container{width:100%;max-width:900px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}";
    html += "@media(max-width:768px){.container{grid-template-columns:1fr;}}";
    html += ".header{grid-column:1/-1;text-align:center;margin-bottom:20px;}";
    html += "h1{background:linear-gradient(45deg,#94a3b8,#cbd5e1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:2.2rem;margin:10px 0;}";
    html += ".mac-badge{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#94a3b8;font-family:monospace;}";
    html += ".crypto-badge{background:rgba(148,163,184,0.12);border:1px solid rgba(148,163,184,0.4);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#cbd5e1;font-weight:bold;}";
    html += ".card{background:rgba(30,41,59,0.45);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,0.5);}";
    html += "h2{font-size:1.2rem;color:#94a3b8;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:10px;margin-top:0;}";
    html += ".metric-grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;}";
    html += ".metric-box{background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.05);padding:12px;border-radius:10px;}";
    html += ".metric-label{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;}";
    html += ".metric-val{font-size:1.3rem;font-weight:bold;color:#f8fafc;margin-top:4px;}";
    html += ".ok{color:#4ade80;}.err{color:#f87171;}.warn{color:#fb923c;}";
    html += ".relay-state{font-size:2rem;font-weight:800;text-align:center;margin:10px 0;}";
    html += ".rbtn{flex:1;padding:16px;border:none;border-radius:10px;color:#0d0e12;font-weight:800;font-size:1rem;cursor:pointer;}";
    html += ".bon{background:#4ade80;}.boff{background:#f87171;}";
    html += ".console{background:#020617;padding:15px;border-radius:10px;height:200px;overflow-y:auto;font-family:'Fira Code',monospace;font-size:0.75rem;color:#cbd5e1;border:1px solid #1e293b;}";
    html += ".log-entry{margin-bottom:4px;border-bottom:1px solid rgba(255,255,255,0.02);padding-bottom:2px;}";
    html += "</style></head><body>";

    html += "<div class='header'><h1>ViPeR Charlie • Relay</h1>";
    html += "<span class='mac-badge'>EQUI: " + macHex + "</span>&nbsp;";
    html += "<span class='mac-badge'>" FIRMWARE_VERSION "</span>&nbsp;";
    html += "<span class='crypto-badge'>ECDH-P384 + AES-128-GCM</span>&nbsp;";
    html += "<a href='/ota' style='color:#f59e0b;font-size:0.8rem;text-decoration:none;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:6px 14px;border-radius:20px;'>&#8679; OTA Update</a>";
    html += "</div>";

    html += "<div class='container'>";

    // Card de controlo manual do relé
    html += "<div class='card'><h2>Controlo do Relé (GPIO " + String(RELAY_PIN) + ")</h2>";
    html += "<div class='relay-state " + String(current_relay_state ? "ok'>LIGADO" : "warn'>DESLIGADO") + "</div>";
    html += "<form method='POST' action='/relay' style='display:flex;gap:12px;'>";
    html += "<button class='rbtn bon' name='state' value='on'>LIGAR</button>";
    html += "<button class='rbtn boff' name='state' value='off'>DESLIGAR</button>";
    html += "</form></div>";

    // Card de estado do nó
    html += "<div class='card'><h2>Estado do Nó</h2><div class='metric-grid'>";
    html += "<div class='metric-box'><div class='metric-label'>IP</div><div class='metric-val' style='font-size:1rem'>" + WiFi.localIP().toString() + "</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>KEX (ECDH)</div><div class='metric-val " + String(kex_completed ? "ok'>OK" : "err'>PENDENTE") + "</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>MQTT</div><div class='metric-val " + String(mqttClient.connected() ? "ok'>Ligado" : "err'>Desligado") + "</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>RSSI</div><div class='metric-val'>" + String(WiFi.RSSI()) + " dBm</div></div>";
    html += "</div></div>";

    // Card de métricas de desempenho
    html += "<div class='card' style='grid-column:1/-1;'><h2>Métricas de Desempenho</h2><div class='metric-grid' style='grid-template-columns:repeat(auto-fit,minmax(140px,1fr));'>";
    html += "<div class='metric-box'><div class='metric-label'>Latência Média</div><div class='metric-val'>" + String(avg_latency, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Jitter</div><div class='metric-val'>" + String(current_jitter, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Throughput</div><div class='metric-val'>" + String(total_bytes_sent / max((unsigned long)1, millis() / 1000), 1) + " B/s</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Perda de Pacotes</div><div class='metric-val'>" + String(packets_sent > 0 ? (1.0 - ((float)packets_received / packets_sent)) * 100.0 : 0, 1) + " %</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Overhead CPU AEAD</div><div class='metric-val'>" + String(crypto_cpu_overhead_us, 0) + " us</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>RAM Cripto</div><div class='metric-val'>" + String(crypto_ram_overhead_kb, 2) + " KB</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Falhas de Prazo (RT)</div><div class='metric-val'>" + String(deadline_violations) + "</div></div>";
    html += "</div></div>";

    html += "<div class='card' style='grid-column:1/-1;'><h2>Logs de Atividade (Últimos 15)</h2><div class='console'>";
    for (int i = 0; i < LOG_SIZE; i++) {
        int idx = (log_ptr + i) % LOG_SIZE;
        if (event_logs[idx] != "") html += "<div class='log-entry'>" + event_logs[idx] + "</div>";
    }
    html += "</div></div>";

    html += "</div></body></html>";
    statusServer.send(200, "text/html", html);
}

void handleRelay() {
    // Botão manual do dashboard: liga/desliga o relé fisicamente
    if (statusServer.hasArg("state")) {
        String s = statusServer.arg("state");
        set_relay(s == "on", "web");
    }
    statusServer.sendHeader("Location", "/");
    statusServer.send(303);
}

void handleOTAPage() {
    if (!statusServer.authenticate(ota_user, ota_pass)) return statusServer.requestAuthentication();
    String html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>OTA</title>";
    html += "<style>body{font-family:monospace;background:#0d0e12;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}";
    html += "h1{color:#94a3b8;}input[type=file]{width:100%;padding:10px;background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:6px;margin:10px 0;box-sizing:border-box;}";
    html += "input[type=submit]{width:100%;padding:12px;background:#94a3b8;color:#0d0e12;border:none;border-radius:6px;font-weight:bold;cursor:pointer;}</style></head><body>";
    html += "<h1>OTA Update</h1><p>" FIRMWARE_VERSION " | " + macHex + "</p>";
    html += "<form method='POST' action='/ota' enctype='multipart/form-data'>";
    html += "<input type='file' name='firmware' accept='.bin'><input type='submit' value='Flash'></form>";
    html += "<a href='/' style='color:#cbd5e1'>&larr; Status</a></body></html>";
    statusServer.send(200, "text/html", html);
}

void setup() {
    Serial.begin(115200); delay(1000);
    Serial.println("\n=== CHARLIE-RELAY (AES-128-GCM + ECDH-P384) ===");
    Serial.println("[FW] " FIRMWARE_VERSION " / " BUILD_TIMESTAMP);

    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, LOW);

    macHex        = getMacHex();
    topic_command = "CHARLIE/" + macHex + "/comando";
    topic_status  = "CHARLIE/" + macHex + "/estado";
    topic_metrics = "CHARLIE/" + macHex + "/metricas";
    topic_handshake = "CHARLIE/" + macHex + "/handshake";

    setup_wifi();
    configTzTime("WET0WEST,M3.5.0/1,M10.5.0/2", "pool.ntp.org");  // hora local (Portugal)

    statusServer.on("/", handleStatus);
    statusServer.on("/relay", HTTP_POST, handleRelay);
    statusServer.on("/ota", HTTP_GET, handleOTAPage);
    statusServer.on("/ota", HTTP_POST,
        []() { statusServer.sendHeader("Connection","close"); statusServer.send(200,"text/plain",Update.hasError()?"FAIL":"OK"); delay(100); ESP.restart(); },
        []() {
            HTTPUpload& u = statusServer.upload();
            if (u.status == UPLOAD_FILE_START) { if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial); }
            else if (u.status == UPLOAD_FILE_WRITE) { if (Update.write(u.buf,u.currentSize)!=u.currentSize) Update.printError(Serial); }
            else if (u.status == UPLOAD_FILE_END) { if (Update.end(true)) Serial.printf("[OTA] OK %u bytes\n",u.totalSize); else Update.printError(Serial); }
        }
    );
    statusServer.begin();
    Serial.println("[OTA] Status activo em http://" + WiFi.localIP().toString() + "/");

    perform_kex();
    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setBufferSize(512);
    mqttClient.setCallback(mqtt_callback);
}

void loop() {
    statusServer.handleClient();
    if (!mqttClient.connected()) connect_mqtt();
    mqttClient.loop();

    unsigned long now = millis();

    if (!kex_completed && (now - last_kex_attempt > KEX_RETRY_INTERVAL)) {
        last_kex_attempt = now; perform_kex();
    } else if (kex_completed && (now - last_key_rotation > KEY_ROTATION_INTERVAL)) {
        perform_kex();
    }

    // Publicação periódica: estado (loopback) + métricas de desempenho
    if (kex_completed && (now - last_telemetry > TELEMETRY_INTERVAL)) {
        last_telemetry = now;
        unsigned long start_task = millis();
        telemetry_sessions++;

        // Publica o estado atual com instrumentação da cifra + loopback
        StaticJsonDocument<256> sdoc;
        sdoc["node"]   = macHex;
        sdoc["fw"]     = FIRMWARE_VERSION;
        sdoc["relay"]  = current_relay_state ? 1 : 0;
        sdoc["status"] = current_relay_state ? "LIGADO" : "DESLIGADO";
        String splain; serializeJson(sdoc, splain);
        uint32_t h0 = ESP.getFreeHeap();
        unsigned long e0 = micros();
        String enc = aesGcm.encrypt(splain);
        crypto_cpu_overhead_us = (float)(micros() - e0);
        crypto_ram_overhead_kb = max(0.0f, (float)(h0 - ESP.getFreeHeap()) / 1024.0f);
        last_publish_micros = micros(); waiting_for_ack = true;
        tracked_publish(topic_status.c_str(), enc.c_str());

        if (millis() - start_task > config_deadline_ms) deadline_violations++;

        float ram_mb = (ESP.getHeapSize() - ESP.getFreeHeap()) / 1024.0 / 1024.0;
        unsigned long up = millis() / 1000;
        float tp    = up > 0 ? (float)total_bytes_sent / up : 0;
        float loss  = packets_sent > 0 ? max(0.0f, (1.0f - ((float)packets_received / packets_sent)) * 100.0f) : 0;
        float vrate = telemetry_sessions > 0 ? ((float)deadline_violations / telemetry_sessions) * 100.0f : 0;

        StaticJsonDocument<512> mdoc;
        mdoc["node"]           = macHex;
        mdoc["fw"]             = FIRMWARE_VERSION;
        mdoc["ram_mb"]         = round(ram_mb * 100.0) / 100.0;
        mdoc["throughput_bps"] = round(tp * 10.0) / 10.0;
        mdoc["loss_pct"]       = round(loss * 100.0) / 100.0;
        mdoc["deadline_pct"]   = round(vrate * 100.0) / 100.0;
        mdoc["avg_lat_ms"]     = round(avg_latency * 100.0) / 100.0;
        mdoc["jitter_ms"]      = round(current_jitter * 100.0) / 100.0;
        mdoc["aead_cpu_us"]    = round(crypto_cpu_overhead_us * 10.0) / 10.0;
        mdoc["aead_ram_kb"]    = round(crypto_ram_overhead_kb * 100.0) / 100.0;
        String mplain; serializeJson(mdoc, mplain);
        String enc_m = aesGcm.encrypt(mplain);
        total_bytes_sent += topic_metrics.length() + enc_m.length() + 2;
        mqttClient.publish(topic_metrics.c_str(), enc_m.c_str());
        if (hs_pending) {
            StaticJsonDocument<256> hdoc;
            hdoc["node"]          = macHex;
            hdoc["fw"]            = FIRMWARE_VERSION;
            hdoc["hs_latency_ms"] = round(hs_latency_ms * 10.0) / 10.0;
            hdoc["hs_req_bytes"]  = hs_req_bytes;
            hdoc["hs_resp_bytes"] = hs_resp_bytes;
            hdoc["kex_algo"]      = "ECDH-secp384r1";
            String hplain; serializeJson(hdoc, hplain);
            String enc_hs = aesGcm.encrypt(hplain);
            total_bytes_sent += topic_handshake.length() + enc_hs.length() + 2;
            mqttClient.publish(topic_handshake.c_str(), enc_hs.c_str());
            hs_pending = false;
        }

    }
}
