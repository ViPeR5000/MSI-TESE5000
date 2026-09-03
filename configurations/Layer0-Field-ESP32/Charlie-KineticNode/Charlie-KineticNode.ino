#include <WiFi.h>
#include <esp_mac.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <Update.h>
#include <time.h>
#include "aes_gcm_wrapper.h"
#include "ecdh_kex.h"
#include "classical_server_cert.h"

// ==========================================
// CONFIGURAÇÕES GERAIS (FASE CHARLIE)
// ==========================================
const char* ssid     = "ViPeR5000-Charlie";
const char* password = "0000011111";

#define FIRMWARE_VERSION  "1.0.0-KN-AES128GCM"
#define FIRMWARE_TYPE     "Charlie-KineticNode"
#define BUILD_TIMESTAMP   __DATE__ " " __TIME__
const char* ota_user = "admin";
const char* ota_pass = "msi-tese";

// Servidor Clássico de Gestão de Chaves (ECDH/ECDSA)
#ifdef CLASSICAL_CERT_READY
const char* kex_server_url = "https://192.168.30.200:8000/kex/exchange";
#else
const char* kex_server_url = "http://192.168.30.200:8000/kex/exchange";
#endif

// Broker MQTT (EMQX — VLAN 30)
const char* mqtt_server = "192.168.30.100";
const int   mqtt_port   = 1883;

const char* ntpServer = "pool.ntp.org";
const char* TZ_INFO   = "WET0WEST,M3.5.0/1,M10.5.0/2";

// Componentes de Rede, WebServer e Criptografia
WiFiClient   espClient;
PubSubClient mqttClient(espClient);
WebServer    server(80);
AesGcmWrapper aesGcm;

String macHex       = "";
String topic_telemetry = "";
String topic_metrics   = "";
String topic_handshake = "";

// ==========================================
// VARIÁVEIS DE SIMULAÇÃO E CONFIGS
// ==========================================
unsigned long telemetry_interval = 5000;
float sim_temp_min = 18.0, sim_temp_max = 30.0;
float sim_hum_min  = 30.0, sim_hum_max  = 80.0;
unsigned long config_deadline_ms = 2000;

float current_temperature = 22.0;
float current_humidity    = 50.0;

// ==========================================
// MONITOR DE PERFORMANCE
// ==========================================
unsigned long total_bytes_sent = 0;
unsigned long packets_sent     = 0;
unsigned long packets_received = 0;
unsigned long wifi_handshake_ms = 0;
unsigned long mqtt_handshake_ms = 0;

unsigned long last_publish_micros = 0;
bool waiting_for_ack = false;
#define MAX_SAMPLES 20
float latency_samples[MAX_SAMPLES];
int sample_idx = 0, num_samples = 0;
float avg_latency = 0, current_jitter = 0;

unsigned long deadline_violations  = 0;
unsigned long telemetry_sessions   = 0;
float crypto_cpu_overhead_us = 0;
float crypto_ram_overhead_kb = 0;

// Controlo de Tempos
unsigned long last_telemetry    = 0;
unsigned long last_key_rotation = 0;
unsigned long last_kex_attempt  = 0;
const unsigned long KEY_ROTATION_INTERVAL = 3600000;
const unsigned long KEX_RETRY_INTERVAL    = 30000;

bool kex_completed = false;

// Instrumentação do handshake (custo assimétrico ECDH — comparável a Kyber no Bravo)
float         hs_latency_ms = 0;   // duração do POST /kex/exchange
unsigned int  hs_req_bytes  = 0;   // corpo enviado (client_pub_b64)
unsigned int  hs_resp_bytes = 0;   // corpo recebido (server_pub_b64)
bool          hs_pending     = false;   // publicar após MQTT ligar

// ==========================================
// SISTEMA DE LOGS
// ==========================================
#define LOG_SIZE 15
String event_logs[LOG_SIZE];
int log_ptr = 0;

void addLog(String msg) {
    struct tm ti;
    char ts[10];
    if (getLocalTime(&ti)) strftime(ts, sizeof(ts), "%H:%M:%S", &ti);
    else strcpy(ts, "??:??:??");
    String e = "[" + String(ts) + "] " + msg;
    event_logs[log_ptr] = e;
    log_ptr = (log_ptr + 1) % LOG_SIZE;
    Serial.println(e);
}

// ==========================================
// FUNÇÕES DE SISTEMA
// ==========================================
String getMacHex() {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char s[13];
    snprintf(s, sizeof(s), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(s);
}

void setup_wifi() {
    unsigned long t = millis();
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    wifi_handshake_ms = millis() - t;
    addLog("WiFi Conectado! IP: " + WiFi.localIP().toString());
}

void perform_kex() {
    addLog("Iniciando ECDH secp384r1 com o Servidor Clássico...");
    if (WiFi.status() != WL_CONNECTED) { addLog("Erro: Sem WiFi."); return; }

    EcdhKex kex;
    String client_pub_b64 = kex.genPublic();
    if (client_pub_b64.isEmpty()) { addLog("Erro: Falha ao gerar chave ECDH."); return; }

    HTTPClient http;
#ifdef CLASSICAL_CERT_READY
    WiFiClientSecure netClient;
    netClient.setTimeout(15);
    netClient.setCACert(CLASSICAL_SERVER_CERT);
    http.begin(netClient, kex_server_url);
    addLog("TLS: certificado clássico configurado (HTTPS).");
#else
    WiFiClient netClient;
    http.begin(netClient, kex_server_url);
    addLog("HTTP sem TLS — executar generate_tls_cert.sh para HTTPS.");
#endif
    http.addHeader("Content-Type", "application/json");

    StaticJsonDocument<256> reqDoc;
    reqDoc["node_id"]        = macHex;
    reqDoc["client_pub_b64"] = client_pub_b64;
    String reqPayload;
    serializeJson(reqDoc, reqPayload);

    unsigned long hs_t0 = millis();
    int code = http.POST(reqPayload);
    if (code == 200) {
        String response = http.getString();
        // Custo assimétrico na rede: latência do round-trip + tamanhos dos corpos.
        hs_latency_ms = (float)(millis() - hs_t0);
        hs_req_bytes  = reqPayload.length();
        hs_resp_bytes = response.length();
        StaticJsonDocument<256> doc;
        if (deserializeJson(doc, response) || !doc["server_pub_b64"]) {
            addLog("Erro JSON na resposta KEX.");
            http.end(); return;
        }
        uint8_t aes_key[16];
        if (!kex.deriveKey(doc["server_pub_b64"], aes_key)) {
            addLog("Erro: Falha HKDF na derivação da chave AES.");
            http.end(); return;
        }
        aesGcm.setKey(aes_key, 16);
        kex_completed = true;
        hs_pending = true;   // publicar métricas do handshake assim que o MQTT estiver ligado
        last_key_rotation = millis();
        addLog("ECDH+HKDF: Chave derivada. Handshake " + String(hs_latency_ms,0) +
               "ms, " + String(hs_req_bytes) + "→" + String(hs_resp_bytes) + " bytes.");
    } else {
        addLog("Falha KEX. HTTP: " + String(code));
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

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    if (String(topic) == topic_telemetry && waiting_for_ack) {
        float lat = (micros() - last_publish_micros) / 1000.0;
        waiting_for_ack = false;
        update_telemetry_stats(lat);
    }
}

void connect_mqtt() {
    while (!mqttClient.connected()) {
        addLog("A ligar ao EMQX...");
        unsigned long t = millis();
        if (mqttClient.connect(macHex.c_str())) {
            mqtt_handshake_ms = millis() - t;
            addLog("MQTT Ligado! Handshake: " + String(mqtt_handshake_ms) + "ms");
            mqttClient.subscribe(topic_telemetry.c_str());
        } else { delay(5000); }
    }
}

// ==========================================
// PAINEL WEB (PORT 80)
// ==========================================
void handleRoot() {
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>ViPeR Charlie - Kinetic Dashboard</title>";
    html += "<style>";
    html += "body{font-family:'Outfit',sans-serif;background:#0d0e12;color:#e2e8f0;margin:0;padding:20px;display:flex;flex-direction:column;align-items:center;}";
    html += ".container{width:100%;max-width:900px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}";
    html += "@media(max-width:768px){.container{grid-template-columns:1fr;}}";
    html += ".header{grid-column:1/-1;text-align:center;margin-bottom:20px;}";
    html += "h1{background:linear-gradient(45deg,#94a3b8,#cbd5e1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:2.2rem;margin:10px 0;}";
    html += ".badge{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#94a3b8;font-family:monospace;}";
    html += ".card{background:rgba(30,41,59,0.45);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:24px;}";
    html += "h2{font-size:1.2rem;color:#94a3b8;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:10px;margin-top:0;}";
    html += ".mg{display:grid;grid-template-columns:1fr 1fr;gap:15px;}";
    html += ".mb{background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.05);padding:12px;border-radius:10px;}";
    html += ".ml{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;}.mv{font-size:1.3rem;font-weight:bold;color:#f8fafc;margin-top:4px;}";
    html += "label{display:block;margin:10px 0 5px;font-size:0.8rem;color:#94a3b8;}";
    html += "input{width:100%;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#fff;box-sizing:border-box;}";
    html += "button{width:100%;padding:12px;background:linear-gradient(45deg,#94a3b8,#cbd5e1);border:none;border-radius:8px;color:#0d0e12;font-weight:bold;cursor:pointer;margin-top:15px;}";
    html += ".con{background:#020617;padding:15px;border-radius:10px;height:240px;overflow-y:auto;font-family:monospace;font-size:0.75rem;color:#4ade80;border:1px solid #1e293b;}";
    html += "</style>";
    html += "<script>setInterval(()=>{if(window.scrollY<100)location.reload();},8000);</script></head><body>";

    html += "<div class='header'>";
    html += "<h1>ViPeR Charlie • Kinetic Data</h1>";
    html += "<span class='badge'>NODE: " + macHex + "</span>&nbsp;";
    html += "<span class='badge'>" FIRMWARE_VERSION "</span>&nbsp;";
    html += "<a href='/ota' style='color:#f59e0b;font-size:0.8rem;text-decoration:none;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:6px 14px;border-radius:20px;'>⬆ OTA Update</a>";
    html += "</div><div class='container'>";

    html += "<div class='card'><h2>Métricas de Desempenho</h2><div class='mg'>";
    html += "<div class='mb'><div class='ml'>Latência Média</div><div class='mv'>" + String(avg_latency,2) + " ms</div></div>";
    html += "<div class='mb'><div class='ml'>Jitter</div><div class='mv'>" + String(current_jitter,2) + " ms</div></div>";
    html += "<div class='mb'><div class='ml'>Throughput</div><div class='mv'>" + String(total_bytes_sent/max((unsigned long)1,millis()/1000),1) + " B/s</div></div>";
    html += "<div class='mb'><div class='ml'>Perda Pacotes</div><div class='mv'>" + String(packets_sent>0?(1.0-((float)packets_received/packets_sent))*100.0:0,1) + " %</div></div>";
    html += "<div class='mb'><div class='ml'>CPU AES-GCM</div><div class='mv'>" + String(crypto_cpu_overhead_us,0) + " us</div></div>";
    html += "<div class='mb'><div class='ml'>RAM Cripto</div><div class='mv'>" + String(crypto_ram_overhead_kb,2) + " KB</div></div>";
    html += "<div class='mb'><div class='ml'>Falhas Prazo</div><div class='mv'>" + String(deadline_violations) + "</div></div>";
    html += "<div class='mb'><div class='ml'>KEX</div><div class='mv' style='color:" + String(kex_completed?"#4ade80":"#f87171") + ";'>" + String(kex_completed?"OK":"PENDENTE") + "</div></div>";
    html += "</div></div>";

    html += "<div class='card'><h2>Configurações</h2><form action='/update' method='POST'>";
    html += "<label>Intervalo TX (ms)</label><input type='number' name='interval' value='" + String(telemetry_interval) + "'>";
    html += "<label>Temp Min/Max (°C)</label><div style='display:flex;gap:10px'>";
    html += "<input type='number' step='0.1' name='tmin' value='" + String(sim_temp_min) + "'>";
    html += "<input type='number' step='0.1' name='tmax' value='" + String(sim_temp_max) + "'></div>";
    html += "<label>Hum Min/Max (%)</label><div style='display:flex;gap:10px'>";
    html += "<input type='number' step='0.1' name='hmin' value='" + String(sim_hum_min) + "'>";
    html += "<input type='number' step='0.1' name='hmax' value='" + String(sim_hum_max) + "'></div>";
    html += "<button type='submit'>GRAVAR</button></form></div>";

    html += "<div class='card' style='grid-column:1/-1;'><h2>Logs (Últimos 15)</h2><div class='con'>";
    for (int i = 0; i < LOG_SIZE; i++) {
        int idx = (log_ptr + i) % LOG_SIZE;
        if (event_logs[idx] != "") html += "<div>" + event_logs[idx] + "</div>";
    }
    html += "</div></div></div></body></html>";
    server.send(200, "text/html", html);
}

void handleOTAPage() {
    if (!server.authenticate(ota_user, ota_pass)) return server.requestAuthentication();
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<title>OTA — " + macHex + "</title>";
    html += "<style>body{font-family:monospace;background:#0d0e12;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}";
    html += "h1{color:#94a3b8;}input[type=file]{width:100%;padding:10px;background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:6px;margin:10px 0;box-sizing:border-box;}";
    html += "input[type=submit]{width:100%;padding:12px;background:#94a3b8;color:#0d0e12;border:none;border-radius:6px;font-weight:bold;cursor:pointer;}</style></head><body>";
    html += "<h1>OTA Firmware Update</h1><p>Node: <b>" + macHex + "</b> | " FIRMWARE_VERSION "</p>";
    html += "<form method='POST' action='/ota' enctype='multipart/form-data'>";
    html += "<input type='file' name='firmware' accept='.bin'>";
    html += "<input type='submit' value='Upload &amp; Flash'></form>";
    html += "<a href='/' style='color:#cbd5e1'>&larr; Dashboard</a></body></html>";
    server.send(200, "text/html", html);
}

void handleUpdate() {
    if (server.hasArg("interval")) telemetry_interval = server.arg("interval").toInt();
    if (server.hasArg("tmin")) sim_temp_min = server.arg("tmin").toFloat();
    if (server.hasArg("tmax")) sim_temp_max = server.arg("tmax").toFloat();
    if (server.hasArg("hmin")) sim_hum_min = server.arg("hmin").toFloat();
    if (server.hasArg("hmax")) sim_hum_max = server.arg("hmax").toFloat();
    addLog("Configurações atualizadas via Web.");
    server.sendHeader("Location", "/"); server.send(303);
}

// ==========================================
// SETUP
// ==========================================
void setup() {
    Serial.begin(115200); delay(1000);
    Serial.println("\n\n=== CHARLIE-KINETICNODE (AES-128-GCM + ECDH-P384) ===");
    Serial.println("[FW] Versão  : " FIRMWARE_VERSION);
    Serial.println("[FW] Build   : " BUILD_TIMESTAMP);

    macHex         = getMacHex();
    topic_telemetry = "CHARLIE/" + macHex + "/telemetria";
    topic_metrics   = "CHARLIE/" + macHex + "/metricas";
    topic_handshake = "CHARLIE/" + macHex + "/handshake";

    setup_wifi();

    configTzTime(TZ_INFO, ntpServer);
    Serial.print("[NTP] A sincronizar...");
    struct tm ti; int r = 0;
    while (!getLocalTime(&ti) && r++ < 15) { Serial.print("."); delay(500); }
    Serial.println(r < 15 ? "\n[NTP] OK" : "\n[NTP] Falha");

    perform_kex();

    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setBufferSize(512);
    mqttClient.setCallback(mqtt_callback);

    server.on("/", handleRoot);
    server.on("/update", HTTP_POST, handleUpdate);
    server.on("/ota", HTTP_GET, handleOTAPage);
    server.on("/ota", HTTP_POST,
        []() { server.sendHeader("Connection","close"); server.send(200,"text/plain",Update.hasError()?"FAIL":"OK"); delay(100); ESP.restart(); },
        []() {
            HTTPUpload& u = server.upload();
            if (u.status == UPLOAD_FILE_START) { if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial); }
            else if (u.status == UPLOAD_FILE_WRITE) { if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial); }
            else if (u.status == UPLOAD_FILE_END) { if (Update.end(true)) Serial.printf("[OTA] OK: %u bytes\n", u.totalSize); else Update.printError(Serial); }
        }
    );
    server.begin();

    String dns = "esp32charlie-" + macHex; dns.toLowerCase();
    if (MDNS.begin(dns.c_str())) Serial.printf("[mDNS] http://%s.local\n", dns.c_str());
}

// ==========================================
// LOOP
// ==========================================
void loop() {
    server.handleClient();
    if (!mqttClient.connected()) connect_mqtt();
    mqttClient.loop();

    unsigned long now = millis();

    // KEX retry 30 s / rotação horária
    if (!kex_completed && (now - last_kex_attempt > KEX_RETRY_INTERVAL)) {
        last_kex_attempt = now;
        addLog("KEX retry...");
        perform_kex();
    } else if (kex_completed && (now - last_key_rotation > KEY_ROTATION_INTERVAL)) {
        addLog("Rotação horária de chaves ECDH...");
        perform_kex();
    }

    if (now - last_telemetry > telemetry_interval) {
        last_telemetry = now;
        unsigned long t0 = millis();
        telemetry_sessions++;

        if (!kex_completed) { addLog("TX abortada: sem chave AES."); return; }

        current_temperature = constrain(current_temperature + (random(-10,11)/100.0), sim_temp_min, sim_temp_max);
        current_humidity    = constrain(current_humidity    + (random(-15,16)/100.0), sim_hum_min,  sim_hum_max);
        addLog("TX: T=" + String(current_temperature,1) + " H=" + String(current_humidity,1));

        StaticJsonDocument<256> tdoc;
        tdoc["node"]  = macHex;
        tdoc["fw"]    = FIRMWARE_VERSION;
        tdoc["build"] = BUILD_TIMESTAMP;
        tdoc["temp"]  = round(current_temperature*100.0)/100.0;
        tdoc["hum"]   = round(current_humidity*100.0)/100.0;
        String tplain; serializeJson(tdoc, tplain);

        uint32_t h0 = ESP.getFreeHeap();
        unsigned long enc0 = micros();
        String enc_tel = aesGcm.encrypt(tplain);
        crypto_cpu_overhead_us = micros() - enc0;
        crypto_ram_overhead_kb = max(0.0f, (float)(h0 - ESP.getFreeHeap()) / 1024.0f);

        last_publish_micros = micros(); waiting_for_ack = true;
        tracked_publish(topic_telemetry.c_str(), enc_tel.c_str());

        if (millis() - t0 > config_deadline_ms) {
            deadline_violations++;
            addLog("ALERTA: Deadline violado! " + String(millis()-t0) + "ms");
        }

        float ram_mb   = (ESP.getHeapSize()-ESP.getFreeHeap())/1024.0/1024.0;
        unsigned long up = millis()/1000;
        float tp       = up > 0 ? (float)total_bytes_sent/up : 0;
        float loss     = packets_sent>0 ? max(0.0f,(1.0f-((float)packets_received/packets_sent))*100.0f) : 0;
        float vrate    = telemetry_sessions>0 ? ((float)deadline_violations/telemetry_sessions)*100.0f : 0;

        StaticJsonDocument<512> mdoc;
        mdoc["node"]           = macHex;
        mdoc["fw"]             = FIRMWARE_VERSION;
        mdoc["build"]          = BUILD_TIMESTAMP;
        mdoc["ram_mb"]         = round(ram_mb*100.0)/100.0;
        mdoc["throughput_bps"] = round(tp*10.0)/10.0;
        mdoc["loss_pct"]       = round(loss*100.0)/100.0;
        mdoc["deadline_pct"]   = round(vrate*100.0)/100.0;
        mdoc["avg_lat_ms"]     = round(avg_latency*100.0)/100.0;
        mdoc["jitter_ms"]      = round(current_jitter*100.0)/100.0;
        mdoc["aead_cpu_us"]    = round(crypto_cpu_overhead_us*10.0)/10.0;
        mdoc["aead_ram_kb"]    = round(crypto_ram_overhead_kb*100.0)/100.0;
        String mplain; serializeJson(mdoc, mplain);
        String encrypted_metrics = aesGcm.encrypt(mplain);

        // Não usar tracked_publish aqui: as métricas não têm loopback e contá-las
        // em packets_sent inflaciona loss_pct para ~50% estruturalmente (igual ao Bravo).
        total_bytes_sent += topic_metrics.length() + encrypted_metrics.length() + 2;
        mqttClient.publish(topic_metrics.c_str(), encrypted_metrics.c_str());

        // Métricas do handshake — publicadas uma vez por handshake (boot/rotação),
        // agora que o MQTT está ligado. Custo assimétrico ECDH (comparável a Kyber).
        if (hs_pending) {
            StaticJsonDocument<256> hdoc;
            hdoc["node"]         = macHex;
            hdoc["fw"]           = FIRMWARE_VERSION;
            hdoc["hs_latency_ms"] = round(hs_latency_ms * 10.0) / 10.0;
            hdoc["hs_req_bytes"]  = hs_req_bytes;
            hdoc["hs_resp_bytes"] = hs_resp_bytes;
            hdoc["kex_algo"]     = "ECDH-secp384r1";
            String hplain; serializeJson(hdoc, hplain);
            String enc_hs = aesGcm.encrypt(hplain);
            total_bytes_sent += topic_handshake.length() + enc_hs.length() + 2;
            mqttClient.publish(topic_handshake.c_str(), enc_hs.c_str());
            hs_pending = false;
        }
    }
}
