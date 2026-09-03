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
#include "mbedtls/base64.h"
#include "ascon_wrapper.h"
#include "pqc_server_cert.h"

// ==========================================
// CONFIGURAÇÕES GERAIS (FASE BRAVO SECURE)
// ==========================================
const char* ssid = "ViPeR5000-Bravo";
const char* password = "0000011111";

#define FIRMWARE_VERSION  "1.1.0-KN-ASCON128"
#define FIRMWARE_TYPE     "Secure-KineticNode"
#define BUILD_TIMESTAMP   __DATE__ " " __TIME__
const char* ota_user = "admin";
const char* ota_pass = "msi-tese";

// Servidor de Gestão de Chaves PQC (Kyber/Dilithium)
#ifdef PQC_CERT_READY
const char* pqc_server_url = "https://192.168.20.200:8000/kem/encapsulate";
#else
const char* pqc_server_url = "http://192.168.20.200:8000/kem/encapsulate";
#endif

// Broker MQTT (EMQX)
const char* mqtt_server = "192.168.20.100";
const int mqtt_port = 1883;

// Configurações do NTP e Timezone
const char* ntpServer = "pool.ntp.org";
const char* TZ_INFO = "WET0WEST,M3.5.0/1,M10.5.0/2"; // Portugal (WET/WEST)

// Componentes de Rede, WebServer e Criptografia
WiFiClient espClient;
PubSubClient mqttClient(espClient);
WebServer server(80);
Ascon128Wrapper asconLwc;

// Identificadores Dinâmicos baseados no MAC Address
String macHex = "";
String topic_telemetry = "";
String topic_metrics = "";
String topic_handshake = "";

// ==========================================
// VARIÁVEIS DE SIMULAÇÃO CINÉTICA E CONFIGS
// ==========================================
unsigned long telemetry_interval = 5000; // ms
float sim_temp_min = 18.0;
float sim_temp_max = 30.0;
float sim_hum_min = 30.0;
float sim_hum_max = 80.0;
unsigned long config_deadline_ms = 2000;

// Estado cinético simulado
float current_temperature = 22.0;
float current_humidity = 50.0;

// ==========================================
// MONITOR DE PERFORMANCE EM TEMPO REAL
// ==========================================
unsigned long total_bytes_sent = 0;
unsigned long packets_sent = 0;
unsigned long packets_received = 0;
unsigned long start_session_time = 0;
unsigned long wifi_handshake_ms = 0;
unsigned long mqtt_handshake_ms = 0;

// Latência e Jitter (Baseado em Loopback Seguro MQTT)
unsigned long last_publish_micros = 0;
bool waiting_for_ack = false;
#define MAX_SAMPLES 20
float latency_samples[MAX_SAMPLES];
int sample_idx = 0;
int num_samples = 0;
float avg_latency = 0;
float current_jitter = 0;

// Métricas de Real-Time e Energia
unsigned long deadline_violations = 0;
unsigned long telemetry_sessions = 0;
float crypto_cpu_overhead_us = 0;
float crypto_ram_overhead_kb = 0;

// Controlo de Tempos de Loop
unsigned long last_telemetry = 0;
unsigned long last_key_rotation = 0;
unsigned long last_pqc_attempt = 0;
const unsigned long KEY_ROTATION_INTERVAL = 3600000; // 1 Hora (NIST SP 800-57)
const unsigned long PQC_RETRY_INTERVAL    = 30000;   // 30 s — retry se handshake falhou

bool pqc_handshake_completed = false;

// Instrumentação do handshake (custo assimétrico Kyber768 — comparável a ECDH no Charlie)
float         hs_latency_ms = 0;   // duração do POST /kem/encapsulate
unsigned int  hs_req_bytes  = 0;   // corpo enviado (node_id)
unsigned int  hs_resp_bytes = 0;   // corpo recebido (ciphertext Kyber + shared secret)
bool          hs_pending     = false;   // publicar após MQTT ligar

// ==========================================
// SISTEMA DE LOGS E EVENTOS
// ==========================================
#define LOG_SIZE 15
String event_logs[LOG_SIZE];
int log_ptr = 0;

void addLog(String msg) {
    struct tm timeinfo;
    char timeStr[10];
    if (getLocalTime(&timeinfo)) {
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &timeinfo);
    } else {
        strcpy(timeStr, "??:??:??");
    }
    String entry = "[" + String(timeStr) + "] " + msg;
    event_logs[log_ptr] = entry;
    log_ptr = (log_ptr + 1) % LOG_SIZE;
    Serial.println(entry);
}

// ==========================================
// FUNÇÕES DE SISTEMA E CRIPTOGRAFIA
// ==========================================

String getMacHex() {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char macStr[13];
    snprintf(macStr, sizeof(macStr), "%02X%02X%02X%02X%02X%02X", 
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

void setup_wifi() {
    unsigned long start_wifi = millis();
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    wifi_handshake_ms = millis() - start_wifi;
    addLog("WiFi Conectado! IP: " + WiFi.localIP().toString());
}

void perform_pqc_key_rotation() {
    addLog("Iniciando Handshake Kyber-768 com o Key Server...");

    if (WiFi.status() != WL_CONNECTED) {
        addLog("Erro: Sem ligação WiFi.");
        return;
    }

    HTTPClient http;
#ifdef PQC_CERT_READY
    WiFiClientSecure netClient;
    netClient.setTimeout(15);
    netClient.setCACert(PQC_SERVER_CERT);
    http.begin(netClient, pqc_server_url);
    addLog("TLS: certificado PQC configurado (HTTPS).");
#else
    WiFiClient netClient;
    http.begin(netClient, pqc_server_url);
    addLog("HTTP sem TLS — executar generate_tls_cert.sh para activar HTTPS.");
#endif
    http.addHeader("Content-Type", "application/json");

    StaticJsonDocument<200> reqDoc;
    reqDoc["node_id"] = macHex;
    String reqPayload;
    serializeJson(reqDoc, reqPayload);

    unsigned long hs_t0 = millis();
    int httpResponseCode = http.POST(reqPayload);

    if (httpResponseCode == 200) {
        String response = http.getString();

        // Custo assimétrico na rede: latência do round-trip + tamanhos dos corpos.
        // O corpo de resposta traz o ciphertext Kyber768 (~1088 B), ~10× o ECDH do Charlie.
        hs_latency_ms = (float)(millis() - hs_t0);
        hs_req_bytes  = reqPayload.length();
        hs_resp_bytes = response.length();

        StaticJsonDocument<2048> doc;
        DeserializationError error = deserializeJson(doc, response);

        if (error) {
            addLog("Falha JSON: " + String(error.f_str()));
            http.end();
            return;
        }

        const char* shared_secret_b64 = doc["shared_secret_b64"];

        // Decodificar o Segredo Quântico Partilhado
        size_t output_len = 0;
        unsigned char shared_secret[64];
        mbedtls_base64_decode(shared_secret, sizeof(shared_secret), &output_len,
                              (const unsigned char*)shared_secret_b64, strlen(shared_secret_b64));

        asconLwc.setKey(shared_secret, output_len);

        pqc_handshake_completed = true;
        hs_pending = true;   // publicar métricas do handshake assim que o MQTT estiver ligado
        last_key_rotation = millis();
        addLog("NIST SP 800-57: Chave ASCON atualizada. Handshake " + String(hs_latency_ms,0) +
               "ms, " + String(hs_req_bytes) + "→" + String(hs_resp_bytes) + " bytes.");
    } else {
        addLog("Falha Kyber. HTTP: " + String(httpResponseCode));
        pqc_handshake_completed = false;
    }
    http.end();
}

// Publicação rastreada para calcular estatísticas de Throughput e contagem de pacotes
bool tracked_publish(const char* topic, const char* payload) {
    total_bytes_sent += strlen(topic) + strlen(payload) + 2; // Estimativa com overhead MQTT
    packets_sent++;
    return mqttClient.publish(topic, payload);
}

void update_telemetry_stats(float new_latency_ms) {
    packets_received++;
    latency_samples[sample_idx] = new_latency_ms;
    sample_idx = (sample_idx + 1) % MAX_SAMPLES;
    if (num_samples < MAX_SAMPLES) num_samples++;

    float sum = 0;
    for (int i = 0; i < num_samples; i++) sum += latency_samples[i];
    avg_latency = sum / num_samples;

    float sq_sum = 0;
    for (int i = 0; i < num_samples; i++) {
        sq_sum += pow(latency_samples[i] - avg_latency, 2);
    }
    current_jitter = sqrt(sq_sum / num_samples);

    Serial.printf("[METRICS] Latency: %.2f ms | Jitter: %.2f ms\n", new_latency_ms, current_jitter);
}

// Callback do MQTT para tratamento de ACK/Echo e cálculo de Latência e Jitter
void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    if (String(topic) == topic_telemetry && waiting_for_ack) {
        unsigned long now_micros = micros();
        float latency_ms = (now_micros - last_publish_micros) / 1000.0;
        waiting_for_ack = false;
        update_telemetry_stats(latency_ms);
    }
}

void connect_mqtt() {
    while (!mqttClient.connected()) {
        addLog("A tentar ligação MQTT ao EMQX...");
        unsigned long start_mqtt = millis();
        
        // Conectar como o ClientID Sovereign baseando-se no MAC Hex
        if (mqttClient.connect(macHex.c_str())) {
            mqtt_handshake_ms = millis() - start_mqtt;
            addLog("MQTT Ligado! Handshake: " + String(mqtt_handshake_ms) + "ms");

            // Subscrever no próprio tópico de telemetria para realizar o cálculo de latência de loopback seguro
            mqttClient.subscribe(topic_telemetry.c_str());
            addLog("Subscrito para Loopback: " + topic_telemetry);
        } else {
            delay(5000);
        }
    }
}

// ==========================================
// PAINEL WEB DE CONTROLO E DASHBOARD (PORT 80)
// ==========================================

void handleRoot() {
    // Rendimento da Interface Gráfica Glassmorphic sofisticada de nível académico
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>ViPeR Bravo - Kinetic Dashboard</title>";
    html += "<style>";
    html += "body{font-family:'Outfit',sans-serif;background:#0d0e12;color:#e2e8f0;margin:0;padding:20px;display:flex;flex-direction:column;align-items:center;min-height:100vh;}";
    html += ".container{width:100%;max-width:900px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}";
    html += "@media(max-width:768px){.container{grid-template-columns:1fr;}}";
    html += ".header{grid-column:1/-1;text-align:center;margin-bottom:20px;}";
    html += "h1{background:linear-gradient(45deg,#f8fafc,#cbd5e1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:2.2rem;margin:10px 0;}";
    html += ".mac-badge{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#e2e8f0;font-family:monospace;letter-spacing:1px;}";
    html += ".card{background:rgba(30,41,59,0.45);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,0.5);}";
    html += "h2{font-size:1.2rem;color:#e2e8f0;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:10px;margin-top:0;}";
    html += ".metric-grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;}";
    html += ".metric-box{background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.05);padding:12px;border-radius:10px;}";
    html += ".metric-label{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;}";
    html += ".metric-val{font-size:1.3rem;font-weight:bold;color:#f8fafc;margin-top:4px;}";
    html += "label{display:block;margin:10px 0 5px;font-size:0.8rem;color:#94a3b8;}";
    html += "input{width:100%;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#fff;box-sizing:border-box;font-size:0.9rem;}";
    html += "button{width:100%;padding:12px;background:linear-gradient(45deg,#cbd5e1,#f8fafc);border:none;border-radius:8px;color:#0d0e12;font-weight:bold;cursor:pointer;transition:all 0.3s ease;margin-top:15px;}";
    html += "button:hover{filter:brightness(1.15);transform:translateY(-1px);}";
    html += ".console{background:#020617;padding:15px;border-radius:10px;height:240px;overflow-y:auto;font-family:'Fira Code',monospace;font-size:0.75rem;color:#4ade80;border:1px solid #1e293b;}";
    html += ".log-entry{margin-bottom:4px;border-bottom:1px solid rgba(255,255,255,0.02);padding-bottom:2px;}";
    html += "</style>";
    html += "<script>setInterval(()=>{if(window.scrollY<100)location.reload();},8000);</script></head><body>";
    
    html += "<div class='header'>";
    html += "<h1>ViPeR Bravo • Kinetic Data</h1>";
    html += "<span class='mac-badge'>EQUI: " + macHex + "</span>&nbsp;";
    html += "<span class='mac-badge'>" FIRMWARE_VERSION "</span>&nbsp;";
    html += "<a href='/ota' style='color:#f59e0b;font-size:0.8rem;text-decoration:none;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);padding:6px 14px;border-radius:20px;'>⬆ OTA Update</a>";
    html += "</div>";

    html += "<div class='container'>";
    
    // Card 1: Métricas de Sistema
    html += "<div class='card'>";
    html += "<h2>Métricas de Desempenho e Redes</h2>";
    html += "<div class='metric-grid'>";
    html += "<div class='metric-box'><div class='metric-label'>Latência Média</div><div class='metric-val'>" + String(avg_latency, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Jitter</div><div class='metric-val'>" + String(current_jitter, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Throughput</div><div class='metric-val'>" + String(total_bytes_sent / max((unsigned long)1, millis()/1000), 1) + " B/s</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Perda de Pacotes</div><div class='metric-val'>" + String(packets_sent > 0 ? (1.0 - ((float)packets_received / packets_sent)) * 100.0 : 0, 1) + " %</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Overhead CPU LWC</div><div class='metric-val'>" + String(crypto_cpu_overhead_us, 0) + " us</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>RAM Cripto</div><div class='metric-val'>" + String(crypto_ram_overhead_kb, 2) + " KB</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Falhas de Prazo (RT)</div><div class='metric-val'>" + String(deadline_violations) + "</div></div>";
    html += "</div>";
    html += "</div>";

    // Card 2: Configurações Dinâmicas
    html += "<div class='card'>";
    html += "<h2>Configurações do Dispositivo</h2>";
    html += "<form action='/update' method='POST'>";
    html += "<label>Intervalo de Transmissão (ms)</label><input type='number' name='interval' value='" + String(telemetry_interval) + "'>";
    html += "<label>Temp Mínima / Máxima (°C)</label><div style='display:flex;gap:10px'>";
    html += "<input type='number' step='0.1' name='tmin' value='" + String(sim_temp_min) + "'>";
    html += "<input type='number' step='0.1' name='tmax' value='" + String(sim_temp_max) + "'></div>";
    html += "<label>Hum Mínima / Máxima (%)</label><div style='display:flex;gap:10px'>";
    html += "<input type='number' step='0.1' name='hmin' value='" + String(sim_hum_min) + "'>";
    html += "<input type='number' step='0.1' name='hmax' value='" + String(sim_hum_max) + "'></div>";
    html += "<button type='submit'>GRAVAR PARÂMETROS</button></form>";
    html += "</div>";

    // Card 3: Console Logs
    html += "<div class='card' style='grid-column: 1/-1;'>";
    html += "<h2>Logs de Segurança e Atividade (Últimos 15)</h2>";
    html += "<div class='console'>";
    for (int i = 0; i < LOG_SIZE; i++) {
        int idx = (log_ptr + i) % LOG_SIZE;
        if (event_logs[idx] != "") {
            html += "<div class='log-entry'>" + event_logs[idx] + "</div>";
        }
    }
    html += "</div></div>";

    html += "</div></body></html>";
    server.send(200, "text/html", html);
}

void handleOTAPage() {
    // if (!server.authenticate(ota_user, ota_pass)) {
    //     return server.requestAuthentication();
    // }
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<title>OTA Update — " + macHex + "</title>";
    html += "<style>body{font-family:monospace;background:#0d0e12;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}";
    html += "h1{color:#f59e0b;}input[type=file]{width:100%;padding:10px;background:#1e293b;border:1px solid #334155;color:#e2e8f0;border-radius:6px;margin:10px 0;box-sizing:border-box;}";
    html += "input[type=submit]{width:100%;padding:12px;background:#f59e0b;color:#0d0e12;border:none;border-radius:6px;font-weight:bold;cursor:pointer;}";
    html += "p{color:#94a3b8;font-size:0.85rem;}</style></head><body>";
    html += "<h1>OTA Firmware Update</h1>";
    html += "<p>Node: <b>" + macHex + "</b> | " FIRMWARE_VERSION "</p>";
    html += "<form method='POST' action='/ota' enctype='multipart/form-data'>";
    html += "<input type='file' name='firmware' accept='.bin'>";
    html += "<input type='submit' value='Upload &amp; Flash'></form>";
    html += "<p>O dispositivo reinicia automaticamente ap&oacute;s o flash.</p>";
    html += "<a href='/' style='color:#e2e8f0'>&larr; Voltar ao Dashboard</a>";
    html += "</body></html>";
    server.send(200, "text/html", html);
}

void handleUpdate() {
    if (server.hasArg("interval")) telemetry_interval = server.arg("interval").toInt();
    if (server.hasArg("tmin")) sim_temp_min = server.arg("tmin").toFloat();
    if (server.hasArg("tmax")) sim_temp_max = server.arg("tmax").toFloat();
    if (server.hasArg("hmin")) sim_hum_min = server.arg("hmin").toFloat();
    if (server.hasArg("hmax")) sim_hum_max = server.arg("hmax").toFloat();

    addLog("Configurações atualizadas via painel Web.");
    server.sendHeader("Location", "/");
    server.send(303);
}

// ==========================================
// CONFIGURAÇÃO INICIAL (SETUP)
// ==========================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n\n=== INICIANDO NÓ CINÉTICO SEGURO (SECURE-KINETICNODE) ===");
    Serial.println("[FW] Versão  : " FIRMWARE_VERSION);
    Serial.println("[FW] Build   : " BUILD_TIMESTAMP);

    // Obter MAC Address Único e inicializar tópicos dinâmicos
    macHex = getMacHex();
    topic_telemetry = "BRAVO/" + macHex + "/telemetria";
    topic_metrics = "BRAVO/" + macHex + "/metricas";
    topic_handshake = "BRAVO/" + macHex + "/handshake";

    setup_wifi();

    // Sincronizar NTP e Hora
    configTzTime(TZ_INFO, ntpServer);
    Serial.print("[NTP] A sincronizar tempo...");
    struct tm timeinfo;
    int retry = 0;
    while (!getLocalTime(&timeinfo) && retry < 15) {
        Serial.print(".");
        delay(500);
        retry++;
    }
    if (retry < 15) {
        Serial.println("\n[NTP] Tempo sincronizado com sucesso.");
    } else {
        Serial.println("\n[NTP] Falha na sincronização inicial de tempo.");
    }

    // Executa handshake quântico inicial
    perform_pqc_key_rotation();

    // Iniciar Broker MQTT
    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setBufferSize(512);
    mqttClient.setCallback(mqtt_callback);

    // Iniciar Servidor Web
    server.on("/", handleRoot);
    server.on("/update", HTTP_POST, handleUpdate);
    server.on("/ota", HTTP_GET, handleOTAPage);
    server.on("/ota", HTTP_POST,
        []() {
            server.sendHeader("Connection", "close");
            server.send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
            delay(100);
            ESP.restart();
        },
        []() {
            HTTPUpload& upload = server.upload();
            if (upload.status == UPLOAD_FILE_START) {
                Serial.printf("[OTA] Upload: %s\n", upload.filename.c_str());
                if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
            } else if (upload.status == UPLOAD_FILE_WRITE) {
                if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) Update.printError(Serial);
            } else if (upload.status == UPLOAD_FILE_END) {
                if (Update.end(true)) Serial.printf("[OTA] Sucesso: %u bytes\n", upload.totalSize);
                else Update.printError(Serial);
            }
        }
    );
    server.begin();
    
    // Iniciar MDNS dinâmico baseado no MAC Address
    String dns_name = "esp32-" + macHex;
    dns_name.toLowerCase();
    if (MDNS.begin(dns_name.c_str())) {
        Serial.printf("[mDNS] Iniciado com sucesso: http://%s.local\n", dns_name.c_str());
    }
}

// ==========================================
// CICLO DE TRABALHO PRINCIPAL (LOOP)
// ==========================================
void loop() {
    server.handleClient();
    if (!mqttClient.connected()) {
        connect_mqtt();
    }
    mqttClient.loop();

    unsigned long now = millis();

    // 1. Rotação Horária de Chaves Simétricas (ou retry de 30 s se handshake falhou)
    if (!pqc_handshake_completed && (now - last_pqc_attempt > PQC_RETRY_INTERVAL)) {
        addLog("PQC retry: sem chave ASCON, a tentar handshake...");
        last_pqc_attempt = now;
        perform_pqc_key_rotation();
    } else if (pqc_handshake_completed && (now - last_key_rotation > KEY_ROTATION_INTERVAL)) {
        addLog("NIST SP 800-57: Rotacionando chaves...");
        perform_pqc_key_rotation();
    }

    // 2. Loop de Telemetria Dinâmica e Métricas
    if (now - last_telemetry > telemetry_interval) {
        last_telemetry = now;
        unsigned long start_task = millis();
        telemetry_sessions++;

        if (!pqc_handshake_completed) {
            addLog("Transmissão abortada: Sem chave ASCON!");
            return;
        }

        // Simulação dinâmica de dados cinéticos com ruído
        current_temperature += (random(-10, 11) / 100.0);
        current_humidity += (random(-15, 16) / 100.0);

        // Manter dados cinéticos limitados nos parâmetros configuráveis
        if (current_temperature < sim_temp_min) current_temperature = sim_temp_min;
        if (current_temperature > sim_temp_max) current_temperature = sim_temp_max;
        if (current_humidity < sim_hum_min) current_humidity = sim_hum_min;
        if (current_humidity > sim_hum_max) current_humidity = sim_hum_max;

        addLog("TX Telemetria: T=" + String(current_temperature, 1) + " H=" + String(current_humidity, 1));

        // Criação de Payload JSON para Telemetria Cinética
        StaticJsonDocument<256> telemetry_doc;
        telemetry_doc["node"]  = macHex;
        telemetry_doc["fw"]    = FIRMWARE_VERSION;
        telemetry_doc["build"] = BUILD_TIMESTAMP;
        telemetry_doc["temp"]  = round(current_temperature * 100.0) / 100.0;
        telemetry_doc["hum"]   = round(current_humidity * 100.0) / 100.0;

        String telemetry_plaintext;
        serializeJson(telemetry_doc, telemetry_plaintext);

        // Encriptar telemetria cinética via LWC ASCON-128
        uint32_t start_heap = ESP.getFreeHeap();
        unsigned long start_enc = micros();
        
        String encrypted_telemetry = asconLwc.encrypt(telemetry_plaintext);
        
        unsigned long end_enc = micros();
        uint32_t end_heap = ESP.getFreeHeap();

        // Armazenar estatísticas criptográficas de overhead
        crypto_cpu_overhead_us = (float)(end_enc - start_enc);
        crypto_ram_overhead_kb = (float)(start_heap - end_heap) / 1024.0;
        if (crypto_ram_overhead_kb < 0) crypto_ram_overhead_kb = 0.0;

        // Inicia contagem de tempo do loopback para medir latência
        last_publish_micros = micros();
        waiting_for_ack = true;

        // Publica a Telemetria Cinética encriptada
        tracked_publish(topic_telemetry.c_str(), encrypted_telemetry.c_str());

        // Verificação de violação de Deadline Real-Time
        unsigned long task_duration = millis() - start_task;
        if (task_duration > config_deadline_ms) {
            deadline_violations++;
            addLog("ALERTA: Violação de deadline do loop! Duração: " + String(task_duration) + " ms");
        }

        // ==========================================
        // GERAÇÃO E CRIPTO-ENVIO DE MÉTRICAS DE REDE
        // ==========================================
        
        // RAM em megabytes
        float ram_usage = (ESP.getHeapSize() - ESP.getFreeHeap()) / 1024.0 / 1024.0;
        
        // Throughput acumulado
        unsigned long uptime_sec = millis() / 1000;
        float throughput = uptime_sec > 0 ? (float)total_bytes_sent / uptime_sec : 0;
        
        // Perda de pacotes
        float loss_rate = packets_sent > 0 ? (1.0 - ((float)packets_received / packets_sent)) * 100.0 : 0;
        if (loss_rate < 0) loss_rate = 0;

        // Rácio de deadlines violadas
        float violation_rate = telemetry_sessions > 0 ? ((float)deadline_violations / telemetry_sessions) * 100.0 : 0;

        // Estimativa energética em mJ (3.3V * 160mA * tempo ativo)

        StaticJsonDocument<512> metrics_doc;
        metrics_doc["node"]  = macHex;
        metrics_doc["fw"]    = FIRMWARE_VERSION;
        metrics_doc["build"] = BUILD_TIMESTAMP;
        metrics_doc["ram_mb"] = round(ram_usage * 100.0) / 100.0;
        metrics_doc["throughput_bps"] = round(throughput * 10.0) / 10.0;
        metrics_doc["loss_pct"] = round(loss_rate * 100.0) / 100.0;
        metrics_doc["deadline_pct"] = round(violation_rate * 100.0) / 100.0;
        metrics_doc["avg_lat_ms"] = round(avg_latency * 100.0) / 100.0;
        metrics_doc["jitter_ms"] = round(current_jitter * 100.0) / 100.0;
        metrics_doc["lwc_cpu_us"] = round(crypto_cpu_overhead_us * 10.0) / 10.0;
        metrics_doc["lwc_ram_kb"] = round(crypto_ram_overhead_kb * 100.0) / 100.0;

        String metrics_plaintext;
        serializeJson(metrics_doc, metrics_plaintext);

        // Encripta as métricas de performance antes do envio para total opacidade e confidencialidade
        String encrypted_metrics = asconLwc.encrypt(metrics_plaintext);

        // Não usar tracked_publish aqui: metrics não tem loopback e contá-la em
        // packets_sent inflacionaria loss_pct para 50% estruturalmente.
        total_bytes_sent += topic_metrics.length() + encrypted_metrics.length() + 2;
        mqttClient.publish(topic_metrics.c_str(), encrypted_metrics.c_str());

        // Métricas do handshake — uma vez por handshake (boot/rotação), agora que o
        // MQTT está ligado. Custo assimétrico Kyber768 (comparável a ECDH no Charlie).
        if (hs_pending) {
            StaticJsonDocument<256> hdoc;
            hdoc["node"]          = macHex;
            hdoc["fw"]            = FIRMWARE_VERSION;
            hdoc["hs_latency_ms"] = round(hs_latency_ms * 10.0) / 10.0;
            hdoc["hs_req_bytes"]  = hs_req_bytes;
            hdoc["hs_resp_bytes"] = hs_resp_bytes;
            hdoc["kex_algo"]      = "Kyber768";
            String hplain; serializeJson(hdoc, hplain);
            String encrypted_hs = asconLwc.encrypt(hplain);
            total_bytes_sent += topic_handshake.length() + encrypted_hs.length() + 2;
            mqttClient.publish(topic_handshake.c_str(), encrypted_hs.c_str());
            hs_pending = false;
        }
    }
}
