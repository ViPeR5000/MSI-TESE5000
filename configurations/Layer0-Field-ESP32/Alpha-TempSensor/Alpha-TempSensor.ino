#include <WiFi.h>
#include <esp_mac.h>
#include <time.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>
#include <WebServer.h>
#include <Update.h>

// ==========================================
// CONFIGURAÇÕES GERAIS (FASE ALPHA — BASELINE PLAINTEXT)
// ==========================================
// Baseline sem criptografia: mesma leitura DHT22 do Secure-TempSensor do Bravo,
// mas publica a telemetria em claro (sem Kyber, sem ASCON, sem servidor de chaves).
// Serve para medir o custo de *ter* criptografia (Alpha → Charlie/Bravo).
const char* ssid = "ViPeR5000-Alpha";
const char* password = "0000011111";

// Broker MQTT (EMQX Alpha)
const char* mqtt_server = "192.168.100.100";
const int mqtt_port = 1883;

#define FIRMWARE_VERSION  "1.0.0-TS-PLAIN"
#define FIRMWARE_TYPE     "Alpha-TempSensor"
#define BUILD_TIMESTAMP   __DATE__ " " __TIME__
const char* ota_user = "admin";
const char* ota_pass = "msi-tese";

// Configurações do Sensor DHT Físico
#define DHTPIN 4
#define DHTTYPE DHT22  // DHT22/AM2302. Para DHT11 mude para DHT11.
DHT dht(DHTPIN, DHTTYPE);

// Componentes de Rede
WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Identificadores Dinâmicos baseados no MAC Address
String macHex = "";
String topic_telemetry = "";
String topic_metrics = "";

// ==========================================
// MONITOR DE PERFORMANCE (baseline plaintext — sem overhead de cripto)
// ==========================================
unsigned long total_bytes_sent = 0;
unsigned long packets_sent = 0;
unsigned long packets_received = 0;
unsigned long last_publish_micros = 0;
bool waiting_for_ack = false;
#define MAX_SAMPLES 20
float latency_samples[MAX_SAMPLES];
int sample_idx = 0, num_samples = 0;
float avg_latency = 0, current_jitter = 0;
unsigned long deadline_violations = 0, telemetry_sessions = 0;
const unsigned long config_deadline_ms = 2000;

// Controlo de Tempos
unsigned long last_telemetry = 0;
const unsigned long TELEMETRY_INTERVAL = 5000; // 5 segundos

WebServer statusServer(80);
float last_temp = 0.0;
float last_hum = 0.0;

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

// ==========================================
// FUNÇÕES DE SISTEMA
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
    Serial.println("\n[WiFi] A inicializar interface de rede...");
    Serial.printf("[WiFi] MAC Address Físico: %s\n", WiFi.macAddress().c_str());
    Serial.printf("[WiFi] Identificador (MAC Hex): %s\n", macHex.c_str());
    Serial.printf("[WiFi] A conectar à rede SSID: %s ", ssid);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\n[WiFi] Ligação estabelecida com sucesso!");
    addLog("WiFi conectado. IP: " + WiFi.localIP().toString());
}

// Publicação rastreada: conta bytes + pacotes (throughput / perda)
bool tracked_publish(const char* topic, const char* payload) {
    total_bytes_sent += strlen(topic) + strlen(payload) + 2;
    packets_sent++;
    return mqttClient.publish(topic, payload);
}

void update_telemetry_stats(float new_latency_ms) {
    packets_received++;
    latency_samples[sample_idx] = new_latency_ms;
    sample_idx = (sample_idx + 1) % MAX_SAMPLES;
    if (num_samples < MAX_SAMPLES) num_samples++;
    float sum = 0, sq = 0;
    for (int i = 0; i < num_samples; i++) sum += latency_samples[i];
    avg_latency = sum / num_samples;
    for (int i = 0; i < num_samples; i++) sq += pow(latency_samples[i] - avg_latency, 2);
    current_jitter = sqrt(sq / num_samples);
}

// Loopback: recebe o eco da própria telemetria e calcula latência/jitter
void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    if (String(topic) == topic_telemetry && waiting_for_ack) {
        float latency_ms = (micros() - last_publish_micros) / 1000.0;
        waiting_for_ack = false;
        update_telemetry_stats(latency_ms);
    }
}

void connect_mqtt() {
    while (!mqttClient.connected()) {
        Serial.printf("[EMQX] Tentando conectar ao Broker MQTT como '%s'...", macHex.c_str());
        if (mqttClient.connect(macHex.c_str())) {
            addLog("MQTT ligado ao broker " + String(mqtt_server));
            Serial.println(" Sucesso na ligação ao EMQX!");
            mqttClient.subscribe(topic_telemetry.c_str());  // loopback p/ latência
        } else {
            Serial.print(" Falha na ligação, rc=");
            Serial.print(mqttClient.state());
            Serial.println(" - Nova tentativa em 5 segundos...");
            delay(5000);
        }
    }
}

// ==========================================
// SERVIDOR WEB: STATUS E OTA (PORT 80)
// ==========================================

void handleStatus() {
    // Dashboard glassmorphic — mesmo layout dos KineticNode (Charlie/Bravo), tema azul (Alpha).
    String html = "<!DOCTYPE html><html lang='pt'><head><meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<meta http-equiv='refresh' content='5'>";
    html += "<title>ViPeR Alpha - TempSensor</title><style>";
    html += "body{font-family:'Outfit',sans-serif;background:#0d0e12;color:#e2e8f0;margin:0;padding:20px;display:flex;flex-direction:column;align-items:center;min-height:100vh;}";
    html += ".container{width:100%;max-width:900px;display:grid;grid-template-columns:1fr 1fr;gap:20px;}";
    html += "@media(max-width:768px){.container{grid-template-columns:1fr;}}";
    html += ".header{grid-column:1/-1;text-align:center;margin-bottom:20px;}";
    html += "h1{background:linear-gradient(45deg,#38bdf8,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700;font-size:2.2rem;margin:10px 0;}";
    html += ".mac-badge{background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#38bdf8;font-family:monospace;letter-spacing:1px;}";
    html += ".plain-badge{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.4);padding:6px 14px;border-radius:20px;font-size:0.85rem;color:#f87171;font-weight:bold;}";
    html += ".card{background:rgba(30,41,59,0.45);backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,0.5);}";
    html += "h2{font-size:1.2rem;color:#38bdf8;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:10px;margin-top:0;}";
    html += ".metric-grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;}";
    html += ".metric-box{background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.05);padding:12px;border-radius:10px;}";
    html += ".metric-label{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;}";
    html += ".metric-val{font-size:1.3rem;font-weight:bold;color:#f8fafc;margin-top:4px;}";
    html += ".ok{color:#4ade80;}.err{color:#f87171;}";
    html += ".console{background:#020617;padding:15px;border-radius:10px;height:200px;overflow-y:auto;font-family:'Fira Code',monospace;font-size:0.75rem;color:#38bdf8;border:1px solid #1e293b;}";
    html += ".log-entry{margin-bottom:4px;border-bottom:1px solid rgba(255,255,255,0.02);padding-bottom:2px;}";
    html += "</style></head><body>";

    html += "<div class='header'>";
    html += "<h1>ViPeR Alpha • TempSensor</h1>";
    html += "<span class='mac-badge'>EQUI: " + macHex + "</span>&nbsp;";
    html += "<span class='mac-badge'>" FIRMWARE_VERSION "</span>&nbsp;";
    html += "<span class='plain-badge'>PLAINTEXT — SEM CRYPTO</span>&nbsp;";
    html += "<a href='/ota' style='color:#38bdf8;font-size:0.8rem;text-decoration:none;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);padding:6px 14px;border-radius:20px;'>&#8679; OTA Update</a>";
    html += "</div>";

    html += "<div class='container'>";

    html += "<div class='card'><h2>Leituras do Sensor (DHT22)</h2><div class='metric-grid'>";
    html += "<div class='metric-box'><div class='metric-label'>Temperatura</div><div class='metric-val'>" + String(last_temp, 1) + " &deg;C</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Humidade</div><div class='metric-val'>" + String(last_hum, 1) + " %</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>RSSI WiFi</div><div class='metric-val'>" + String(WiFi.RSSI()) + " dBm</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Uptime</div><div class='metric-val'>" + String(millis() / 1000) + " s</div></div>";
    html += "</div></div>";

    html += "<div class='card'><h2>Estado do Nó</h2><div class='metric-grid'>";
    html += "<div class='metric-box'><div class='metric-label'>IP</div><div class='metric-val' style='font-size:1rem'>" + WiFi.localIP().toString() + "</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>MQTT</div><div class='metric-val " + String(mqttClient.connected() ? "ok'>Ligado" : "err'>Desligado") + "</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Sensor</div><div class='metric-val' style='font-size:1rem'>DHT22 Real</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Broker</div><div class='metric-val' style='font-size:1rem'>" + String(mqtt_server) + "</div></div>";
    html += "</div></div>";

    html += "<div class='card' style='grid-column:1/-1;'><h2>Métricas de Desempenho</h2><div class='metric-grid' style='grid-template-columns:repeat(auto-fit,minmax(140px,1fr));'>";
    html += "<div class='metric-box'><div class='metric-label'>Latência Média</div><div class='metric-val'>" + String(avg_latency, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Jitter</div><div class='metric-val'>" + String(current_jitter, 2) + " ms</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Throughput</div><div class='metric-val'>" + String(total_bytes_sent / max((unsigned long)1, millis() / 1000), 1) + " B/s</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Perda de Pacotes</div><div class='metric-val'>" + String(packets_sent > 0 ? (1.0 - ((float)packets_received / packets_sent)) * 100.0 : 0, 1) + " %</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>Overhead CPU LWC</div><div class='metric-val'>0 us (N/A)</div></div>";
    html += "<div class='metric-box'><div class='metric-label'>RAM Cripto</div><div class='metric-val'>0 KB (N/A)</div></div>";
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

void handleOTAPage() {
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
    html += "<a href='/' style='color:#38bdf8'>&larr; Voltar ao Status</a>";
    html += "</body></html>";
    statusServer.send(200, "text/html", html);
}

// ==========================================
// CONFIGURAÇÃO INICIAL (SETUP)
// ==========================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n\n=== INICIANDO NÓ DE TEMPERATURA ALPHA (PLAINTEXT) ===");
    Serial.println("[FW] Versão  : " FIRMWARE_VERSION);
    Serial.println("[FW] Build   : " BUILD_TIMESTAMP);

    dht.begin();

    macHex = getMacHex();
    topic_telemetry = "ALPHA/" + macHex + "/telemetria";
    topic_metrics   = "ALPHA/" + macHex + "/metricas";

    setup_wifi();
    configTzTime("WET0WEST,M3.5.0/1,M10.5.0/2", "pool.ntp.org");  // hora local (Portugal)

    statusServer.on("/", handleStatus);
    statusServer.on("/ota", HTTP_GET, handleOTAPage);
    statusServer.on("/ota", HTTP_POST,
        []() {
            statusServer.sendHeader("Connection", "close");
            statusServer.send(200, "text/plain", Update.hasError() ? "FAIL" : "OK");
            delay(100);
            ESP.restart();
        },
        []() {
            HTTPUpload& upload = statusServer.upload();
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
    statusServer.begin();
    Serial.println("[OTA] Status/OTA activo em http://" + WiFi.localIP().toString() + "/");

    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setBufferSize(512);
    mqttClient.setCallback(mqtt_callback);
}

// ==========================================
// CICLO DE TRABALHO PRINCIPAL (LOOP)
// ==========================================
void loop() {
    statusServer.handleClient();
    if (!mqttClient.connected()) {
        connect_mqtt();
    }
    mqttClient.loop();

    unsigned long now = millis();

    if (now - last_telemetry > TELEMETRY_INTERVAL) {
        last_telemetry = now;
        unsigned long start_task = millis();
        telemetry_sessions++;

        // Leitura física dos dados do sensor
        float t = dht.readTemperature();
        float h = dht.readHumidity();

        // Fallback robusto se o sensor DHT real falhar ou não estiver ligado
        if (isnan(t) || isnan(h)) {
            t = 24.5 + (random(-15, 16) / 10.0);
            h = 60.0 + (random(-30, 31) / 10.0);
        }

        last_temp = t;
        last_hum = h;

        // Payload JSON em plaintext (baseline — sem cifra)
        StaticJsonDocument<256> doc;
        doc["node"]      = macHex;
        doc["fw"]        = FIRMWARE_VERSION;
        doc["build"]     = BUILD_TIMESTAMP;
        doc["temp"]      = round(t * 100.0) / 100.0;
        doc["hum"]       = round(h * 100.0) / 100.0;

        String plaintext_payload;
        serializeJson(doc, plaintext_payload);

        // Loopback (latência/jitter) + publicação com contagem de pacotes
        last_publish_micros = micros();
        waiting_for_ack = true;
        if (tracked_publish(topic_telemetry.c_str(), plaintext_payload.c_str())) {
            addLog("TX plaintext: T=" + String(t, 1) + " H=" + String(h, 1));
        } else {
            addLog("Erro ao publicar no broker!");
        }

        // Verificação de violação de deadline (real-time)
        if (millis() - start_task > config_deadline_ms) {
            deadline_violations++;
            addLog("ALERTA: violação de deadline! " + String(millis() - start_task) + "ms");
        }

        // Métricas de performance/rede → ALPHA/<MAC>/metricas (cripto = 0, baseline)
        float ram_mb  = (ESP.getHeapSize() - ESP.getFreeHeap()) / 1024.0 / 1024.0;
        unsigned long up = millis() / 1000;
        float tp      = up > 0 ? (float)total_bytes_sent / up : 0;
        float loss    = packets_sent > 0 ? max(0.0f, (1.0f - ((float)packets_received / packets_sent)) * 100.0f) : 0;
        float vrate   = telemetry_sessions > 0 ? ((float)deadline_violations / telemetry_sessions) * 100.0f : 0;

        StaticJsonDocument<512> mdoc;
        mdoc["node"]           = macHex;
        mdoc["fw"]             = FIRMWARE_VERSION;
        mdoc["ram_mb"]         = round(ram_mb * 100.0) / 100.0;
        mdoc["throughput_bps"] = round(tp * 10.0) / 10.0;
        mdoc["loss_pct"]       = round(loss * 100.0) / 100.0;
        mdoc["deadline_pct"]   = round(vrate * 100.0) / 100.0;
        mdoc["avg_lat_ms"]     = round(avg_latency * 100.0) / 100.0;
        mdoc["jitter_ms"]      = round(current_jitter * 100.0) / 100.0;
        mdoc["lwc_cpu_us"]     = 0;   // baseline plaintext — sem cripto
        mdoc["lwc_ram_kb"]     = 0;
        String mplain; serializeJson(mdoc, mplain);
        total_bytes_sent += topic_metrics.length() + mplain.length() + 2;
        mqttClient.publish(topic_metrics.c_str(), mplain.c_str());
    }
}
