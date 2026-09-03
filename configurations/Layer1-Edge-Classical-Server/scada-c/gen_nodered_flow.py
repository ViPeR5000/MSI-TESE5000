#!/usr/bin/env python3
"""Gera o flows.json do Node-RED do viper-scada-c (fase Charlie, dashboard 1.0)."""
import json

def nid(x): return f"charlie{x:04d}"
n = 0
def newid():
    global n; n += 1; return nid(n)

flows = []

TAB    = newid()
BROKER = newid()
UIBASE = newid()
UITAB  = newid()
G_TEL  = newid()   # grupo Telemetria
G_CTL  = newid()   # grupo Controlo/Cripto

flows += [
  {"id":TAB,"type":"tab","label":"Charlie SCADA","disabled":False,"info":""},
  {"id":BROKER,"type":"mqtt-broker","name":"EMQX Charlie","broker":"192.168.30.100",
   "port":"1883","clientid":"scada-c-nodered","autoConnect":True,"keepalive":"60","cleansession":True},
  {"id":UIBASE,"type":"ui_base","theme":{"name":"theme-dark","lightTheme":{"default":True},
   "darkTheme":{"default":True,"baseColor":"#a78bfa","baseFont":"-apple-system"},
   "customTheme":{"name":"Charlie","default":False}},"site":{"name":"MSI-TESE Charlie",
   "hideToolbar":"false","allowSwipe":"false","dateFormat":"DD/MM/YYYY HH:mm:ss"}},
  {"id":UITAB,"type":"ui_tab","name":"Charlie","icon":"security","order":1,"disabled":False},
  {"id":G_TEL,"type":"ui_group","name":"Telemetria (AES-128-GCM)","tab":UITAB,"order":1,"disp":True,"width":"6"},
  {"id":G_CTL,"type":"ui_group","name":"Cripto & Controlo","tab":UITAB,"order":2,"disp":True,"width":"6"},
]

# ── Aquisição da chave de sessão do servidor PKI clássico ───────────────────────
INJ   = newid(); SETURL = newid(); HTTP = newid(); CACHE = newid()
flows += [
  {"id":INJ,"type":"inject","name":"tick 15s","props":[{"p":"payload"}],
   "repeat":"15","once":True,"onceDelay":"2","topic":"","payload":"","payloadType":"date",
   "wires":[[SETURL]],"z":TAB},
  {"id":SETURL,"type":"function","name":"set PKI url","func":
   "msg.method='GET';msg.url='http://192.168.30.200:8000/monitor';msg.headers={};return msg;",
   "outputs":1,"wires":[[HTTP]],"z":TAB},
  {"id":HTTP,"type":"http request","name":"","method":"use","ret":"txt","url":"","wires":[[CACHE]],"z":TAB},
  {"id":CACHE,"type":"function","name":"cache keys","func":
   "var d;try{d=JSON.parse(msg.payload);}catch(e){node.error('PKI parse: '+e);return null;}\n"
   "var keys=(d.recent_session_keys_b64||[]).slice().reverse();\n"
   "var ak=d.active_session_key_b64;\n"
   "if(ak&&keys.indexOf(ak)<0)keys.unshift(ak);\n"
   "if(keys.length){flow.set('pki_keys',keys);node.status({fill:'green',shape:'dot',text:keys.length+' chave(s)'});}\n"
   "else node.status({fill:'yellow',shape:'ring',text:'sem chave no PKI'});\n"
   "return null;","outputs":1,"wires":[[]],"z":TAB},
]

# ── Função de decifração AES-128-GCM (partilhada telem/estado) ───────────────────
DEC_FUNC = (
 "const crypto=global.get('crypto');\n"
 "var keys=flow.get('pki_keys')||[];\n"
 "if(!keys.length){node.status({fill:'red',shape:'ring',text:'sem chave'});return null;}\n"
 "var wire=Buffer.from(String(msg.payload).trim(),'base64');\n"
 "if(wire.length<28){return null;}\n"
 "var iv=wire.subarray(0,12),tag=wire.subarray(wire.length-16),ct=wire.subarray(12,wire.length-16);\n"
 "for(var i=0;i<keys.length;i++){\n"
 "  try{\n"
 "    var key=Buffer.from(keys[i],'base64').subarray(0,16);\n"
 "    var dec=crypto.createDecipheriv('aes-128-gcm',key,iv);dec.setAuthTag(tag);\n"
 "    var pt=Buffer.concat([dec.update(ct),dec.final()]);\n"
 "    msg.payload=JSON.parse(pt.toString('utf8'));\n"
 "    var parts=String(msg.topic).split('/');\n"
 "    if(parts.length>=2){if(parts[2]==='estado')flow.set('relay_mac',parts[1]);else flow.set('node_mac',parts[1]);}\n"
 "    node.status({fill:'green',shape:'dot',text:'OK'});\n"
 "    return msg;\n"
 "  }catch(e){}\n"
 "}\n"
 "node.status({fill:'yellow',shape:'ring',text:'decrypt falhou'});return null;\n"
)

# ── Telemetria: MQTT → decrypt → gauges + texto ─────────────────────────────────
MQTT_T = newid(); DEC_T = newid(); F_TEMP = newid(); F_HUM = newid()
G_TEMP = newid(); G_HUM = newid(); T_UPD = newid()
flows += [
  {"id":MQTT_T,"type":"mqtt in","name":"","topic":"CHARLIE/+/telemetria","qos":"1",
   "broker":BROKER,"wires":[[DEC_T]],"z":TAB},
  {"id":DEC_T,"type":"function","name":"AES-GCM decrypt telem","func":DEC_FUNC,
   "outputs":1,"wires":[[F_TEMP,F_HUM,T_UPD]],"z":TAB},
  {"id":F_TEMP,"type":"function","name":"temp","func":
   "if(msg.payload.temp===undefined)return null;msg.payload=msg.payload.temp;return msg;",
   "outputs":1,"wires":[[G_TEMP]],"z":TAB},
  {"id":F_HUM,"type":"function","name":"hum","func":
   "if(msg.payload.hum===undefined)return null;msg.payload=msg.payload.hum;return msg;",
   "outputs":1,"wires":[[G_HUM]],"z":TAB},
  {"id":G_TEMP,"type":"ui_gauge","name":"","group":G_TEL,"order":1,"width":"3","height":"3",
   "gtype":"gage","title":"Temperatura","label":"°C","format":"{{value}}","min":"0","max":"50",
   "colors":["#00b3fd","#5cd65c","#ff4d4d"],"seg1":"20","seg2":"35","z":TAB},
  {"id":G_HUM,"type":"ui_gauge","name":"","group":G_TEL,"order":2,"width":"3","height":"3",
   "gtype":"gage","title":"Humidade","label":"%","format":"{{value}}","min":"0","max":"100",
   "colors":["#f5d142","#5cd65c","#00b3fd"],"seg1":"30","seg2":"70","z":TAB},
  {"id":T_UPD,"type":"ui_text","name":"","group":G_TEL,"order":3,"width":"6","height":"1",
   "label":"Nó","format":"{{msg.payload.node}} · {{msg.payload.fw}}","layout":"row-spread","z":TAB},
]

# ── Estado do relay + botões de comando (activam quando o relay for gravado) ─────
MQTT_E = newid(); DEC_E = newid(); T_RELAY = newid()
BTN_ON = newid(); BTN_OFF = newid(); ENC = newid(); MQTT_OUT = newid(); T_STACK = newid()
ENC_FUNC = (
 "const crypto=global.get('crypto');\n"
 "var keys=flow.get('pki_keys')||[];\n"
 "var mac=flow.get('relay_mac')||flow.get('node_mac');\n"
 "if(!keys.length||!mac){node.warn('sem chave ou MAC de relay');return null;}\n"
 "var key=Buffer.from(keys[0],'base64').subarray(0,16);\n"
 "var iv=crypto.randomBytes(12);\n"
 "var cmd=Buffer.from(JSON.stringify({command:msg.payload}),'utf8');\n"
 "var c=crypto.createCipheriv('aes-128-gcm',key,iv);\n"
 "var ct=Buffer.concat([c.update(cmd),c.final()]);var tag=c.getAuthTag();\n"
 "msg.payload=Buffer.concat([iv,ct,tag]).toString('base64');\n"
 "msg.topic='CHARLIE/'+mac+'/comando';return msg;\n"
)
flows += [
  {"id":MQTT_E,"type":"mqtt in","name":"","topic":"CHARLIE/+/estado","qos":"1",
   "broker":BROKER,"wires":[[DEC_E]],"z":TAB},
  {"id":DEC_E,"type":"function","name":"AES-GCM decrypt estado","func":DEC_FUNC,
   "outputs":1,"wires":[[T_RELAY]],"z":TAB},
  {"id":T_RELAY,"type":"ui_text","name":"","group":G_CTL,"order":1,"width":"6","height":"1",
   "label":"Estado do Relay","format":"{{msg.payload.relay ? 'LIGADO' : 'DESLIGADO'}}",
   "layout":"row-spread","z":TAB},
  {"id":BTN_ON,"type":"ui_button","name":"","group":G_CTL,"order":2,"width":"3","height":"1",
   "label":"Relay ON","color":"","bgcolor":"#2e7d32","payload":"relay_on","payloadType":"str",
   "topic":"","wires":[[ENC]],"z":TAB},
  {"id":BTN_OFF,"type":"ui_button","name":"","group":G_CTL,"order":3,"width":"3","height":"1",
   "label":"Relay OFF","color":"","bgcolor":"#c62828","payload":"relay_off","payloadType":"str",
   "topic":"","wires":[[ENC]],"z":TAB},
  {"id":ENC,"type":"function","name":"AES-GCM encrypt cmd","func":ENC_FUNC,
   "outputs":1,"wires":[[MQTT_OUT]],"z":TAB},
  {"id":MQTT_OUT,"type":"mqtt out","name":"","topic":"","qos":"1","retain":"","broker":BROKER,"wires":[],"z":TAB},
  {"id":T_STACK,"type":"ui_text","name":"","group":G_CTL,"order":4,"width":"6","height":"1",
   "label":"Stack","format":"ECDH-P384 + AES-128-GCM","layout":"row-spread","z":TAB},
]

print(json.dumps(flows, indent=1))
