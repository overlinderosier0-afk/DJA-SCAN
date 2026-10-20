// ============================================================
// DJA-SCAN v5.0 - edition OLED
// ESP32 + OLED 0.96" SSD1306 (I2C 0x3C) + joystick analogique
//
// Modules :
//   V1 : scanner WiFi (liste reseaux + details)
//   V2 : detecteur de deauth (mode promiscuous, saut de canaux)
//   V3 : scanner BLE (appareils Bluetooth Low Energy)
//   V4 : sniffer de probe requests (100% passif)
//   V5 : trafic WiFi en direct + cartographie AP <-> clients
//
// REGLE permanente : aucun outil d'attaque (deauth offensive,
// beacon/BLE spam, evil portal, karma/rogue AP, capture de
// handshakes/PMKID). Modules uniquement passifs/defensifs :
// scan, sniff, detection.
//
// Cablage :
//   OLED : VCC->3.3V, GND->GND, SDA->GPIO21, SCL->GPIO22
//   Joystick: VCC->3.3V (!), GND->GND, VRX->GPIO34, VRY->GPIO35, SW->GPIO32
//
// Libs : "Adafruit GFX Library" "Adafruit SSD1306"
// Partition : huge_app (le BLE est volumineux)
// ============================================================

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <BLEDevice.h>
#include <BLEScan.h>

// ---------- config ----------
#define SCREEN_W   128
#define SCREEN_H   64
#define OLED_ADDR  0x3C
#define OLED_SDA   21
#define OLED_SCL   22

#define JOY_VRX    34
#define JOY_VRY    35
#define JOY_SW     32
#define JOY_CENTER 2048
#define JOY_DEAD   700
#define JOY_REPEAT 220

#define HOP_MS     400
#define CH_MAX     13
#define DET_WIN_MS 10000
#define DET_WIN_N  24
#define DET_WARN   5
#define DET_ALERT  15

#define BLE_SCAN_S   5

#define PROBE_RING   16
#define PROBE_MAX    48

#define ASSOC_RING   32
#define AP_MAX       16
#define CLI_MAX      8

Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &Wire, -1);

// ---------- navigation ----------
enum Screen { MENU, SCAN_LIST, NET_DETAIL, DETECTOR, BLE_LIST, BLE_DETAIL,
              PROBE_LIST, PROBE_DETAIL, TRAFFIC, CLI_AP, CLI_LIST, ABOUT };
Screen screen = MENU;
int menuIdx = 0, menuTop = 0;
int listIdx = 0, listTop = 0;
int bleIdx = 0, bleTop = 0;
int probeIdx = 0, probeTop = 0;
int apIdx = 0, apTop = 0;
int cliIdx = 0, cliTop = 0;

const char* menuItems[] = { "Scan WiFi", "Detect. deauth", "Scan BLE",
                            "Sniff probes", "Trafic", "Clients", "A propos" };
const int menuLen = sizeof(menuItems) / sizeof(menuItems[0]);
#define MENU_ROWS 5

unsigned long lastJoy = 0;
bool swPrev = HIGH;

// ---------- donnees WiFi ----------
struct Net {
  String ssid;
  String bssid;
  int    rssi;
  int    ch;
  int    enc;
};
Net* nets = nullptr;
int  netCount = 0;

// ---------- donnees BLE ----------
struct BleDev {
  String name;
  String addr;
  int    rssi;
  int    txPower;
};
BleDev* bleDevs = nullptr;
int     bleCount = 0;
bool    bleInited = false;

// ---------- sniffer (promiscuous) ----------
enum SniffMode { SNIFF_OFF, SNIFF_DEAUTH, SNIFF_PROBE, SNIFF_TRAFFIC, SNIFF_CLIENTS };
volatile SniffMode sniffMode = SNIFF_OFF;

volatile int detDeauth = 0;
volatile int detDisassoc = 0;
volatile unsigned long detTimes[DET_WIN_N];
volatile uint8_t detN = 0;

volatile uint32_t cntBeacon = 0, cntProbeReq = 0, cntProbeResp = 0;
volatile uint32_t cntAuth = 0, cntData = 0, cntOther = 0;

int hopChannel = 1;
unsigned long sniffStartMs = 0;
unsigned long lastHopMs = 0;
unsigned long lastDrawMs = 0;

// --- probes (V4) ---
struct ProbeRaw {
  uint8_t mac[6];
  char    ssid[33];
  int8_t  rssi;
};
volatile ProbeRaw probeRing[PROBE_RING];
volatile uint8_t probeW = 0;
volatile uint8_t probeR = 0;

struct ProbeSeen {
  uint8_t mac[6];
  char    ssid[33];
  int     count;
  int     rssi;
};
ProbeSeen* probes = nullptr;
int probeCount = 0;

// --- associations AP<->clients (V5) ---
struct AssocRaw {
  uint8_t ap[6];
  uint8_t cli[6];
};
volatile AssocRaw assocRing[ASSOC_RING];
volatile uint8_t assocW = 0;
volatile uint8_t assocR = 0;

struct ApEntry {
  uint8_t bssid[6];
  uint8_t cli[CLI_MAX][6];
  uint8_t nCli;
  uint32_t frames;
};
ApEntry apList[AP_MAX];
int apCount = 0;

// Callback promiscuous unique
void IRAM_ATTR promiscCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* p = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;
  uint8_t fc = p[0];

  if (type == WIFI_PKT_MGMT) {
    if (fc == 0x80) cntBeacon++;
    else if (fc == 0x40) {
      cntProbeReq++;
      if (sniffMode == SNIFF_PROBE && len > 26) {
        uint8_t ssidLen = p[25];
        if (ssidLen > 32) ssidLen = 32;
        if (26 + ssidLen <= len) {
          uint8_t w = probeW;
          uint8_t nw = (w + 1) % PROBE_RING;
          if (nw == probeR) probeR = (probeR + 1) % PROBE_RING;
          for (int i = 0; i < 6; i++) probeRing[w].mac[i] = p[10 + i];
          for (int i = 0; i < ssidLen; i++) probeRing[w].ssid[i] = (char)p[26 + i];
          probeRing[w].ssid[ssidLen] = 0;
          probeRing[w].rssi = pkt->rx_ctrl.rssi;
          probeW = nw;
        }
      }
    }
    else if (fc == 0x50) cntProbeResp++;
    else if (fc == 0xB0) cntAuth++;
    else if (fc == 0xC0) {
      detDeauth++;
      for (int i = DET_WIN_N - 1; i > 0; i--) detTimes[i] = detTimes[i - 1];
      detTimes[0] = millis();
      if (detN < DET_WIN_N) detN++;
    }
    else if (fc == 0xA0) detDisassoc++;
    else cntOther++;
  } else {
    cntData++;
    if (sniffMode == SNIFF_CLIENTS) {
      uint8_t b1 = p[1];
      bool toDS = b1 & 0x01, fromDS = b1 & 0x02;
      const uint8_t *ap = nullptr, *cli = nullptr;
      if (toDS && !fromDS)       { ap = p + 4; cli = p + 10; }
      else if (!toDS && fromDS)  { ap = p + 10; cli = p + 4; }
      if (ap && cli && !(cli[0] & 0x01)) {
        uint8_t w = assocW;
        uint8_t nw = (w + 1) % ASSOC_RING;
        if (nw == assocR) assocR = (assocR + 1) % ASSOC_RING;
        for (int i = 0; i < 6; i++) { assocRing[w].ap[i] = ap[i]; assocRing[w].cli[i] = cli[i]; }
        assocW = nw;
      }
    }
  }
}

int detRate() {
  unsigned long now = millis();
  int c = 0;
  for (int i = 0; i < detN; i++)
    if (now - detTimes[i] < DET_WIN_MS) c++;
  return c;
}

void snifferStart(SniffMode m, Screen s) {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(50);
  sniffMode = m;
  hopChannel = 1;
  esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(promiscCb);
  esp_wifi_set_promiscuous(true);
  sniffStartMs = millis();
  lastHopMs = millis();
  lastDrawMs = 0;
  screen = s;
}

void snifferStop() {
  esp_wifi_set_promiscuous(false);
  sniffMode = SNIFF_OFF;
  screen = MENU;
  drawMenu();
}

void detectorStart() {
  detDeauth = 0; detDisassoc = 0; detN = 0;
  snifferStart(SNIFF_DEAUTH, DETECTOR);
  Serial.println("Detecteur deauth actif");
}

void detectorDraw() {
  int rate = detRate();
  unsigned long el = (millis() - sniffStartMs) / 1000;

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print("DEAUTH DETECT ch");
  display.println(hopChannel);
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  display.setCursor(0, 14);
  display.print("Deauth: "); display.print(detDeauth);
  display.print(" ("); display.print(rate); display.println("/10s)");
  display.setCursor(0, 26);
  display.print("Disassoc: "); display.println(detDisassoc);
  display.setCursor(0, 38);
  display.print("T+"); display.print(el); display.println("s");

  display.setCursor(0, 50);
  if (rate >= DET_ALERT) {
    display.fillRect(0, 49, 127, 15, SSD1306_WHITE);
    display.setTextColor(SSD1306_BLACK);
    display.setCursor(4, 53);
    display.print("! ATTAQUE ?");
  } else if (rate >= DET_WARN) {
    display.print("Etat: SUSPECT");
  } else {
    display.print("Etat: calme");
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

// ---------- module probe sniffer ----------
void probeStart() {
  if (probes) { delete[] probes; probes = nullptr; }
  probes = new ProbeSeen[PROBE_MAX];
  probeCount = 0;
  probeW = 0; probeR = 0;
  probeIdx = 0; probeTop = 0;
  snifferStart(SNIFF_PROBE, PROBE_LIST);
  Serial.println("Sniffer probes actif");
}

bool probeDrain() {
  bool changed = false;
  while (probeR != probeW) {
    uint8_t mac[6];
    char ss[33];
    int8_t rssi;
    uint8_t r = probeR;
    for (int i = 0; i < 6; i++) mac[i] = probeRing[r].mac[i];
    for (int i = 0; i < 33; i++) { ss[i] = probeRing[r].ssid[i]; if (ss[i] == 0) break; }
    rssi = probeRing[r].rssi;
    probeR = (r + 1) % PROBE_RING;

    int idx = -1;
    for (int i = 0; i < probeCount; i++) {
      bool sameMac = true;
      for (int k = 0; k < 6; k++) if (probes[i].mac[k] != mac[k]) { sameMac = false; break; }
      if (sameMac && strcmp(probes[i].ssid, ss) == 0) { idx = i; break; }
    }
    if (idx >= 0) {
      probes[idx].count++;
      probes[idx].rssi = rssi;
    } else if (probeCount < PROBE_MAX) {
      for (int k = 0; k < 6; k++) probes[probeCount].mac[k] = mac[k];
      strcpy(probes[probeCount].ssid, ss);
      probes[probeCount].count = 1;
      probes[probeCount].rssi = rssi;
      probeCount++;
    }
    changed = true;
  }
  return changed;
}

String macStr(const uint8_t* m) {
  char b[18];
  snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(b);
}

String macShort(const uint8_t* m) {
  char b[9];
  snprintf(b, sizeof(b), "%02x:%02x:%02x", m[3], m[4], m[5]);
  return String(b);
}

void probeDrawList() {
  if (probeCount <= 0) {
    oledHeader("Sniff probes");
    display.setCursor(0, 24);
    display.println("En ecoute...");
    display.setCursor(0, 40);
    display.println("<- : retour");
    display.display();
    return;
  }
  if (probeIdx < probeTop) probeTop = probeIdx;
  if (probeIdx > probeTop + 3) probeTop = probeIdx - 3;

  oledHeader("Probes: " + String(probeCount));
  for (int i = 0; i < 4 && probeTop + i < probeCount; i++) {
    int b = probeTop + i;
    int y = 14 + i * 12;
    String nm = strlen(probes[b].ssid) ? String(probes[b].ssid) : "<tous>";
    if (b == probeIdx) {
      display.fillRect(0, y, 127, 11, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println((nm + " x" + String(probes[b].count)).substring(0, 20));
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

void probeDrawDetail() {
  ProbeSeen &d = probes[probeIdx];
  oledHeader("Probe " + String(probeIdx + 1) + "/" + String(probeCount));
  display.setCursor(0, 14);
  String nm = strlen(d.ssid) ? String(d.ssid) : "<tous>";
  display.println(nm.substring(0, 21));
  display.println(macStr(d.mac));
  display.print(d.rssi); display.print(" dBm  x"); display.println(d.count);
  display.display();
}

// ---------- module trafic ----------
void trafficStart() {
  cntBeacon = cntProbeReq = cntProbeResp = 0;
  cntAuth = cntData = cntOther = 0;
  snifferStart(SNIFF_TRAFFIC, TRAFFIC);
  Serial.println("Trafic actif");
}

void trafficDraw() {
  unsigned long el = (millis() - sniffStartMs) / 1000;
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print("TRAFIC ch");
  display.print(hopChannel);
  display.print(" T+"); display.print(el); display.println("s");
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  display.setCursor(0, 14); display.print("Beacon  "); display.println(cntBeacon);
  display.setCursor(0, 24);
  display.print("Probe "); display.print(cntProbeReq);
  display.print("/"); display.println(cntProbeResp);
  display.setCursor(0, 34);
  display.print("Auth "); display.print(cntAuth);
  display.print(" Dea "); display.println(detDeauth);
  display.setCursor(0, 44); display.print("Data    "); display.println(cntData);
  display.setCursor(0, 54); display.print("Autres  "); display.println(cntOther);
  display.display();
}

// ---------- module clients ----------
void clientsStart() {
  apCount = 0;
  assocW = 0; assocR = 0;
  apIdx = 0; apTop = 0; cliIdx = 0; cliTop = 0;
  snifferStart(SNIFF_CLIENTS, CLI_AP);
  Serial.println("Clients actif");
}

bool assocDrain() {
  bool changed = false;
  while (assocR != assocW) {
    uint8_t ap[6], cli[6];
    uint8_t r = assocR;
    for (int i = 0; i < 6; i++) { ap[i] = assocRing[r].ap[i]; cli[i] = assocRing[r].cli[i]; }
    assocR = (r + 1) % ASSOC_RING;

    int ai = -1;
    for (int i = 0; i < apCount; i++) {
      bool same = true;
      for (int k = 0; k < 6; k++) if (apList[i].bssid[k] != ap[k]) { same = false; break; }
      if (same) { ai = i; break; }
    }
    if (ai < 0 && apCount < AP_MAX) {
      ai = apCount++;
      for (int k = 0; k < 6; k++) apList[ai].bssid[k] = ap[k];
      apList[ai].nCli = 0;
      apList[ai].frames = 0;
    }
    if (ai >= 0) {
      apList[ai].frames++;
      int ci = -1;
      for (int i = 0; i < apList[ai].nCli; i++) {
        bool same = true;
        for (int k = 0; k < 6; k++) if (apList[ai].cli[i][k] != cli[k]) { same = false; break; }
        if (same) { ci = i; break; }
      }
      if (ci < 0 && apList[ai].nCli < CLI_MAX) {
        ci = apList[ai].nCli++;
        for (int k = 0; k < 6; k++) apList[ai].cli[ci][k] = cli[k];
      }
    }
    changed = true;
  }
  return changed;
}

void cliApDraw() {
  if (apCount <= 0) {
    oledHeader("Clients");
    display.setCursor(0, 24);
    display.println("En ecoute...");
    display.setCursor(0, 40);
    display.println("<- : retour");
    display.display();
    return;
  }
  if (apIdx < apTop) apTop = apIdx;
  if (apIdx > apTop + 3) apTop = apIdx - 3;

  oledHeader("AP: " + String(apCount));
  for (int i = 0; i < 4 && apTop + i < apCount; i++) {
    int a = apTop + i;
    int y = 14 + i * 12;
    if (a == apIdx) {
      display.fillRect(0, y, 127, 11, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println((".." + macShort(apList[a].bssid) + " " +
                     String(apList[a].nCli) + "cli").substring(0, 20));
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

void cliListDraw() {
  ApEntry &a = apList[apIdx];
  oledHeader(".." + macShort(a.bssid) + " (" + String(a.nCli) + ")");
  if (a.nCli == 0) {
    display.setCursor(0, 24);
    display.println("Aucun client vu.");
    display.display();
    return;
  }
  if (cliIdx < cliTop) cliTop = cliIdx;
  if (cliIdx > cliTop + 3) cliTop = cliIdx - 3;
  for (int i = 0; i < 4 && cliTop + i < a.nCli; i++) {
    int c = cliTop + i;
    int y = 14 + i * 12;
    if (c == cliIdx) {
      display.fillRect(0, y, 127, 11, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println(macStr(a.cli[c]));
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

// ---------- helpers ----------
String encName(int e) {
  switch (e) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    default:                        return "?";
  }
}

void oledHeader(const String& t) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(t);
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
}

// ---------- module WiFi ----------
void drawMenu() {
  if (menuIdx < menuTop) menuTop = menuIdx;
  if (menuIdx > menuTop + MENU_ROWS - 1) menuTop = menuIdx - MENU_ROWS + 1;
  oledHeader("DJA-SCAN v5.0");
  for (int i = 0; i < MENU_ROWS && menuTop + i < menuLen; i++) {
    int m = menuTop + i;
    int y = 13 + i * 10;
    if (m == menuIdx) {
      display.fillRect(0, y, 127, 10, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println(menuItems[m]);
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

void doScan() {
  if (nets) { delete[] nets; nets = nullptr; }
  netCount = 0;
  esp_wifi_set_promiscuous(false);
  sniffMode = SNIFF_OFF;
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  oledHeader("Scan WiFi");
  display.setCursor(0, 24);
  display.println("Scan en cours...");
  display.display();

  netCount = WiFi.scanNetworks();
  Serial.printf("Scan WiFi: %d reseaux\n", netCount);
  if (netCount > 0) {
    nets = new Net[netCount];
    for (int i = 0; i < netCount; i++) {
      nets[i].ssid  = WiFi.SSID(i);
      nets[i].bssid = WiFi.BSSIDstr(i);
      nets[i].rssi  = WiFi.RSSI(i);
      nets[i].ch    = WiFi.channel(i);
      nets[i].enc   = WiFi.encryptionType(i);
    }
  }
  WiFi.scanDelete();
  listIdx = 0; listTop = 0;
  screen = SCAN_LIST;
  drawList();
}

void drawList() {
  if (netCount <= 0) {
    oledHeader("Scan WiFi");
    display.setCursor(0, 24);
    display.println("Aucun reseau.");
    display.setCursor(0, 40);
    display.println("<- : retour");
    display.display();
    return;
  }
  if (listIdx < listTop) listTop = listIdx;
  if (listIdx > listTop + 3) listTop = listIdx - 3;

  oledHeader("Reseaux: " + String(netCount));
  for (int i = 0; i < 4 && listTop + i < netCount; i++) {
    int n = listTop + i;
    int y = 14 + i * 12;
    String ssid = nets[n].ssid;
    if (ssid.length() == 0) ssid = "<sans nom>";
    if (n == listIdx) {
      display.fillRect(0, y, 127, 11, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println((ssid + " " + String(nets[n].rssi) + "dBm").substring(0, 20));
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

void drawDetail() {
  Net &n = nets[listIdx];
  oledHeader("Detail " + String(listIdx + 1) + "/" + String(netCount));
  display.setCursor(0, 14);
  String s = n.ssid.length() ? n.ssid : "<sans nom>";
  display.println(s.substring(0, 21));
  display.println(n.bssid);
  display.print(n.rssi); display.print(" dBm   CH "); display.println(n.ch);
  display.print("Securite: "); display.println(encName(n.enc));
  display.display();
}

// ---------- module BLE ----------
void bleScanStart() {
  if (!bleInited) { BLEDevice::init("DJA-SCAN"); bleInited = true; }

  if (bleDevs) { delete[] bleDevs; bleDevs = nullptr; }
  bleCount = 0;

  oledHeader("Scan BLE");
  display.setCursor(0, 24);
  display.println("Ecoute 5s...");
  display.display();

  BLEScan* pScan = BLEDevice::getScan();
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);
  BLEScanResults* res = pScan->start(BLE_SCAN_S, false);
  int n = res->getCount();
  Serial.printf("Scan BLE: %d paquets\n", n);

  BleDev tmp[64];
  int tc = 0;
  for (int i = 0; i < n && tc < 64; i++) {
    BLEAdvertisedDevice d = res->getDevice(i);
    String addr = d.getAddress().toString().c_str();
    bool seen = false;
    for (int j = 0; j < tc; j++) if (tmp[j].addr == addr) { seen = true; break; }
    if (seen) continue;
    tmp[tc].addr = addr;
    tmp[tc].name = d.haveName() ? d.getName().c_str() : "";
    tmp[tc].rssi = d.getRSSI();
    tmp[tc].txPower = d.haveTXPower() ? d.getTXPower() : -999;
    tc++;
  }
  for (int i = 0; i < tc - 1; i++)
    for (int j = i + 1; j < tc; j++)
      if (tmp[j].rssi > tmp[i].rssi) { BleDev t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t; }

  if (tc > 0) {
    bleDevs = new BleDev[tc];
    for (int i = 0; i < tc; i++) bleDevs[i] = tmp[i];
  }
  bleCount = tc;
  pScan->clearResults();

  bleIdx = 0; bleTop = 0;
  screen = BLE_LIST;
  bleDrawList();
}

void bleDrawList() {
  if (bleCount <= 0) {
    oledHeader("Scan BLE");
    display.setCursor(0, 24);
    display.println("Aucun appareil.");
    display.setCursor(0, 40);
    display.println("<- : retour");
    display.display();
    return;
  }
  if (bleIdx < bleTop) bleTop = bleIdx;
  if (bleIdx > bleTop + 3) bleTop = bleIdx - 3;

  oledHeader("BLE: " + String(bleCount));
  for (int i = 0; i < 4 && bleTop + i < bleCount; i++) {
    int b = bleTop + i;
    int y = 14 + i * 12;
    String nm = bleDevs[b].name;
    if (nm.length() == 0) nm = bleDevs[b].addr;
    if (b == bleIdx) {
      display.fillRect(0, y, 127, 11, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(4, y + 2);
    display.println((nm + " " + String(bleDevs[b].rssi) + "dBm").substring(0, 20));
  }
  display.setTextColor(SSD1306_WHITE);
  display.display();
}

void bleDrawDetail() {
  BleDev &d = bleDevs[bleIdx];
  oledHeader("BLE " + String(bleIdx + 1) + "/" + String(bleCount));
  display.setCursor(0, 14);
  String nm = d.name.length() ? d.name : "<sans nom>";
  display.println(nm.substring(0, 21));
  display.println(d.addr);
  display.print(d.rssi); display.print(" dBm");
  if (d.txPower != -999) { display.print("  TX "); display.print(d.txPower); }
  display.println();
  display.display();
}

// ---------- entrees ----------
int joyDir(int pin) {
  int v = analogRead(pin);
  if (v < JOY_CENTER - JOY_DEAD) return -1;
  if (v > JOY_CENTER + JOY_DEAD) return  1;
  return 0;
}

void handleInput(int dy, int dx, bool clicked) {
  switch (screen) {
    case MENU:
      if (dy == -1)      { menuIdx = (menuIdx + menuLen - 1) % menuLen; drawMenu(); }
      else if (dy == 1)  { menuIdx = (menuIdx + 1) % menuLen; drawMenu(); }
      else if (clicked) {
        if (menuIdx == 0)      doScan();
        else if (menuIdx == 1) detectorStart();
        else if (menuIdx == 2) bleScanStart();
        else if (menuIdx == 3) probeStart();
        else if (menuIdx == 4) trafficStart();
        else if (menuIdx == 5) clientsStart();
        else { screen = ABOUT; oledHeader("A propos");
               display.setCursor(0, 24); display.println("DJA-SCAN v5.0");
               display.setCursor(0, 38); display.println("par DJA"); display.display(); }
      }
      break;

    case SCAN_LIST:
      if (dy == -1 && listIdx > 0)              { listIdx--; drawList(); }
      else if (dy == 1 && listIdx < netCount-1) { listIdx++; drawList(); }
      else if (clicked && netCount > 0)         { screen = NET_DETAIL; drawDetail(); }
      else if (dx == -1)                        { screen = MENU; drawMenu(); }
      break;

    case NET_DETAIL:
      if (clicked || dx == -1)                  { screen = SCAN_LIST; drawList(); }
      break;

    case DETECTOR:
      if (clicked || dx == -1)                  { snifferStop(); }
      break;

    case BLE_LIST:
      if (dy == -1 && bleIdx > 0)               { bleIdx--; bleDrawList(); }
      else if (dy == 1 && bleIdx < bleCount-1)  { bleIdx++; bleDrawList(); }
      else if (clicked && bleCount > 0)         { screen = BLE_DETAIL; bleDrawDetail(); }
      else if (dx == -1)                        { screen = MENU; drawMenu(); }
      break;

    case BLE_DETAIL:
      if (clicked || dx == -1)                  { screen = BLE_LIST; bleDrawList(); }
      break;

    case PROBE_LIST:
      if (dy == -1 && probeIdx > 0)             { probeIdx--; probeDrawList(); }
      else if (dy == 1 && probeIdx < probeCount - 1) { probeIdx++; probeDrawList(); }
      else if (clicked && probeCount > 0)       { screen = PROBE_DETAIL; probeDrawDetail(); }
      else if (dx == -1)                        { snifferStop(); }
      break;

    case PROBE_DETAIL:
      if (clicked || dx == -1)                  { screen = PROBE_LIST; probeDrawList(); }
      break;

    case TRAFFIC:
      if (clicked || dx == -1)                  { snifferStop(); }
      break;

    case CLI_AP:
      if (dy == -1 && apIdx > 0)                { apIdx--; cliApDraw(); }
      else if (dy == 1 && apIdx < apCount - 1)  { apIdx++; cliApDraw(); }
      else if (clicked && apCount > 0)          { screen = CLI_LIST; cliIdx = 0; cliTop = 0; cliListDraw(); }
      else if (dx == -1)                        { snifferStop(); }
      break;

    case CLI_LIST:
      if (dy == -1 && cliIdx > 0)               { cliIdx--; cliListDraw(); }
      else if (dy == 1) {
        ApEntry &a = apList[apIdx];
        if (cliIdx < a.nCli - 1) { cliIdx++; cliListDraw(); }
      }
      else if (clicked || dx == -1)             { screen = CLI_AP; cliApDraw(); }
      break;

    case ABOUT:
      if (clicked || dx != 0)                   { screen = MENU; drawMenu(); }
      break;
  }
}

// ---------- animation de demarrage ----------
void bootAnim() {
  // phase 1 : impulsions radar
  for (int step = 0; step < 3; step++) {
    for (int r = 4; r <= 46; r += 7) {
      display.clearDisplay();
      display.drawCircle(26, 32, r, SSD1306_WHITE);
      display.fillCircle(26, 32, 2, SSD1306_WHITE);
      display.setTextSize(2);
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(58, 18);
      display.print("DJA");
      display.setTextSize(1);
      display.setCursor(58, 38);
      display.print("SCAN");
      display.display();
      delay(45);
    }
  }
  // phase 2 : barre de chargement
  for (int w = 0; w <= 116; w += 10) {
    display.clearDisplay();
    display.setTextSize(2);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(14, 8);
    display.print("DJA-SCAN");
    display.setTextSize(1);
    display.setCursor(40, 30);
    display.println("v5.0");
    display.drawRect(4, 46, 120, 12, SSD1306_WHITE);
    if (w > 0) display.fillRect(6, 48, w, 8, SSD1306_WHITE);
    display.display();
    delay(45);
  }
  delay(250);
}

void setup() {
  Serial.begin(115200);
  pinMode(JOY_SW, INPUT_PULLUP);
  analogReadResolution(12);
  randomSeed(analogRead(JOY_VRX) ^ analogRead(JOY_VRY));

  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("OLED introuvable a 0x3C !");
    for (;;) delay(1000);
  }
  bootAnim();
  drawMenu();
}

void loop() {
  unsigned long now = millis();

  if (screen == DETECTOR) {
    if (now - lastHopMs > HOP_MS) {
      lastHopMs = now;
      hopChannel++;
      if (hopChannel > CH_MAX) hopChannel = 1;
      esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
    }
    if (now - lastDrawMs > 500) {
      lastDrawMs = now;
      detectorDraw();
    }
  }

  if (screen == PROBE_LIST || screen == PROBE_DETAIL) {
    if (now - lastHopMs > HOP_MS) {
      lastHopMs = now;
      hopChannel++;
      if (hopChannel > CH_MAX) hopChannel = 1;
      esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
    }
    if (probeDrain() && screen == PROBE_LIST) probeDrawList();
    if (now - lastDrawMs > 1000) {
      lastDrawMs = now;
      if (screen == PROBE_LIST) probeDrawList();
    }
  }

  if (screen == TRAFFIC) {
    if (now - lastHopMs > HOP_MS) {
      lastHopMs = now;
      hopChannel++;
      if (hopChannel > CH_MAX) hopChannel = 1;
      esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
    }
    if (now - lastDrawMs > 500) {
      lastDrawMs = now;
      trafficDraw();
    }
  }

  if (screen == CLI_AP || screen == CLI_LIST) {
    if (now - lastHopMs > HOP_MS) {
      lastHopMs = now;
      hopChannel++;
      if (hopChannel > CH_MAX) hopChannel = 1;
      esp_wifi_set_channel(hopChannel, WIFI_SECOND_CHAN_NONE);
    }
    if (assocDrain()) {
      if (screen == CLI_AP) cliApDraw();
      else cliListDraw();
    }
    if (now - lastDrawMs > 1000) {
      lastDrawMs = now;
      if (screen == CLI_AP) cliApDraw();
    }
  }

  bool sw = digitalRead(JOY_SW);
  bool clicked = (swPrev == HIGH && sw == LOW);
  swPrev = sw;

  if (now - lastJoy > JOY_REPEAT) {
    int dy = joyDir(JOY_VRY);
    int dx = joyDir(JOY_VRX);
    if (dy != 0 || dx != 0 || clicked) {
      lastJoy = now;
      handleInput(dy, dx, clicked);
    }
  }
}
